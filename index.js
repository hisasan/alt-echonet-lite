'use strict';

const dgram = require('dgram');
const os    = require('os');
const debug = require('debug')('echonet-lite');

// EHD(固定)
const EHD = 0x1081;
// ESV
const ESV = {
    SetI:       0x60,
    SetC:       0x61,
    Get:        0x62,
    INF_REQ:    0x63,
    SetGet:     0x6e,
    Set_Res:    0x71,
    Get_Res:    0x72,
    INF:        0x73,
    INFC:       0x74,
    INFC_Res:   0x7a,
    SetGet_Res: 0x7e,
    SetI_SNA:   0x50,
    SetC_SNA:   0x51,
    Get_SNA:    0x52,
    INF_SNA:    0x53,
    SetGet_SNA: 0x5e
};
// マルチキャストアドレス
const multicastAddress = '224.0.23.0';
// ポート番号
const PORT = 3610;
// クラス／インスタンス
const CONTROLLER  = 0x05ff01;
const NODEPROFILE = 0x0ef001;

// IPv4のサブネットアドレスを得る
function getSubnet() {
    const interfaces = os.networkInterfaces();
    for (let iface in interfaces) {
        for (let i = 0; i < interfaces[iface].length; i++) {
            let a = interfaces[iface][i];
            if (a.family == 'IPv4' && a.internal == false && a.hasOwnProperty('address')) {
                let subnet     = a.address.match(/([0-9]+.[0-9]+.[0-9].)[0-9]+/);
                let subnetbits = a.cidr.match(/[0-9\\.]+\/([0-9]+)/);
                if (subnet && subnetbits) {
                    // ネットワーク負荷が大きくなるため、最大8ビット分(254台)までしか探索しない。
                    let netbits = Math.min(8, 32-subnetbits[1]);
                    return { prefix:subnet[1], min:1, max:(2**netbits)-2 };
                }
            }
        }
    }
    return null;
}

// 探索フレーム作成
function createSearchFrame(self) {
    return createFrame(self, {
        SEOJ: NODEPROFILE,
        DEOJ: NODEPROFILE,
        ESV:  'Get',
        EPC:  0x83,
        EDT:  []
    });
}

// サブネット内のノードをユニキャストで探索する
function searchUnicast(self) {
    let subnet = getSubnet();
    if (subnet == null) {
        console.error("searchUnicast: can't get sub-network address.");
        return;
    }
    for (let i = subnet.min; i <= subnet.max; i++) {
        send(subnet.prefix + i, createSearchFrame(self));
    }
}

// サブネット内のノードをマルチキャストで探索する
function searchMulticast(self) {
    send(multicastAddress, createSearchFrame(self));
}

// サブネット内のノードを探索する
function searchNode(self) {
    switch (self.cfg.SEARCHTYPE) {
    default:
    case 0:
        searchMulticast(self);
        break;
    case 1:
        searchUnicast(self);
        break;
    }
}

// 自局インタフェースのアドレスか確認する
function isOwnAddress(address) {
    const interfaces = os.networkInterfaces();
    for (let iface in interfaces) {
        for (let i = 0; i < interfaces[iface].length; i++) {
            if (interfaces[iface][i].address == address) {
                return true;
            }
        }
    }
    return false;
}

// ノード更新
function updateNode(self, node, prop, v) {
    if (!self.elnode.hasOwnProperty(node)) {
        self.elnode[node] = {que:[], run:null, node:node};
    }
    self.elnode[node].date = new Date();
    self.elnode[node][prop] = v;
}

// IPアドレスに対応するノードを得る
function getAddressNode(self, address) {
    for (let node in self.elnode) {
        if (self.elnode[node].address == address) {
            return node;
        }
    }
    return null;
}

// コールバック呼び出し
function goCallback(node, info, callback) {
    if (typeof(callback) == 'function') {
        if (info.hasOwnProperty('frame') && info.hasOwnProperty('rinfo')) {
            let frame   = info.frame;
            let remote  = info.rinfo;
            // すべてのプロパティを切り出してフレームの健全性をみる
            // OPCやPDCに対してPROP長さが足りない場合は異常とする
            let objList = [];
            for (let i = 0, j = 0; i < frame.OPC; i++) {
                let obj = { node:node, instance:frame.SEOJ, rinfo:remote };
                obj.ESV = frame.ESV;
                obj.EPC = frame.PROP[j++];
                obj.PDC = frame.PROP[j++];
                obj.EDT = [];
                for (let k = 0; k < obj.PDC; k++) {
                    if (frame.PROP.length <= j) {
                        callback({node:node, error:'frame error'});
                        return;
                    }
                    obj.EDT[k] = frame.PROP[j++];
                }
                objList.push(obj);
            }
            // プロパティごとにコールバックする
            for (let i = 0; i < objList.length; i++) {
                callback(objList[i]);
            }
        } else if (info.hasOwnProperty('error')) {
            callback({node:node, error:info.error});
        } else {
            console.error('Unsupport callback');
        }
    }
}

// キューから次の要求を取り出して送信
function sender(p) {
    let f = p.f;
    if (f.run == null) {
        if (f.que.length > 0) {
            // 次の要求をキューから取得
            f.run = f.que.shift();
            f.retry = p.self.cfg.RETRYCOUNT;
        }
    }

    if (f.run) {
        // 要求送信
        f.resp  = 0;
        if ([ESV.SetC, ESV.Get, ESV.SetGet, ESV.INF_REQ, ESV.INFC].indexOf(getESVbyte(f.run.ESV)) >= 0) {
            // 応答要要求
            let callback = undefined;
            if (((f.run.DEOJ & 0xff) == 0) || (f.address == multicastAddress)) {
                // マルチキャスト要求
                // 全インスタンス宛ての要求もマルチキャスト扱いにする
                callback = receiverMulticast;
            } else {
                // ユニキャスト要求
                callback = receiverUnicast;
            }
            let tid = generateTID(p.self, callback, p.self.cfg.QUERYTIMEOUT, p);
            f.run.buf.writeUIntBE(tid, 2, 2);
            send(f.address, f.run.buf);
        } else if ([ESV.SetI].indexOf(getESVbyte(f.run.ESV)) >= 0) {
            // 応答不要要求
            send(f.address, f.run.buf);
            setTimeout(nextQuery, p.self.cfg.NORESINTERVAL, p);
        } else {
            // 通知または応答
            send(f.address, f.run.buf);
            setTimeout(nextQuery, p.self.cfg.NOTIFYINTERVAL, p);
        }
    }
}

// 次の要求
function nextQuery(p) {
    p.f.run = null;
    sender(p);
}

// ユニキャスト要求の応答確認
// 正常応答またはリトライオーバーでコールバックする
function receiverUnicast(info, p) {
    let f = p.f;
    if (f.run) {
        // 応答確認
        const resESV = {
            SetC:   'Set_Res',
            Get:    'Get_Res',
            SetGet: 'SetGet_Res',
            INF_REQ:'INF',
            INFC:   'INFC_Res'
        };
        if (!info.hasOwnProperty('frame') || !info.frame.hasOwnProperty('ESV') ||
            resESV[getESVsymbol(f.run.ESV)] != info.frame.ESV) {
            // 異常応答もしくはタイムアウト
            let reason;
            if (info.hasOwnProperty('frame') && info.frame.hasOwnProperty('ESV')) {
                // 応答のESVが正常応答ではない
                reason = 'ESV:' + info.frame.ESV;
            } else if (info.hasOwnProperty('error')) {
                // タイムアウトなどのエラー
                reason = 'error:' + info.error;
            }
            if (--f.retry >= 0) {
                // リトライ間隔あけて再送
                debug(`Retry elnode=${f.node} inst=${toHexString(f.run.DEOJ, 6)} ESV=${f.run.ESV} EPC=${toHexString(f.run.EPC, 2)} reason=${reason}`);
                setTimeout(sender, p.self.cfg.RETRYINTERVAL, p);
                return true;
            }
            // リトライオーバー
            console.error(`Retry over elnode=${f.node} inst=${toHexString(f.run.DEOJ, 6)} ESV=${f.run.ESV} EPC=${toHexString(f.run.EPC, 2)} reason=${reason}`);
        }
        // 完了コールバック
        goCallback(f.node, info, f.run.callback);
    }
    // 次の要求へ
    nextQuery(p);
    return true;
}

// マルチキャスト要求の応答確認
// タイムアウトまでの全ての応答でコールバックする
function receiverMulticast(info, p) {
    let f = p.f;
    if (f.run) {
        // 応答確認
        if (info.hasOwnProperty('frame') && info.frame.hasOwnProperty('ESV')) {
            // タイムアウトまで他の応答も待つ
            if (!isOwnAddress(info.rinfo.address)) {
                // 自局が送信したもの以外はすべて受け入れる
                goCallback(f.node, info, f.run.callback);
                f.resp++;
            }
            return false;
        }
        // タイムアウト
        if (f.resp == 0) {
            // 応答が1つもなかった場合はエラーでコールバックする
            goCallback(f.node, info, f.run.callback);
        }
    }
    // 次の要求へ
    nextQuery(p);
    return true;
}

// ノードのキューに要求を積む
function pushExec(self, node, frame) {
    // コールバック指定がない場合はグローバルコールバックを使用
    frame.callback = frame.callback || self.callback;
    if (self.elnode.hasOwnProperty(node)) {
        self.elnode[node].que.push(frame);
        if (self.elnode[node].run == null) {
            // sender停止時に起動する
            sender({self:self, f:self.elnode[node]});
        }
    } else {
        frame.callback({node:node, error:'unknown node'});
    }
}

// ESVの数値を指定して、シンボル（SetIなど)を得る
function getESVsymbol(v) {
    for (let it in ESV) {
        if (ESV[it] == v) {
            return it;
        }
    }
    return '?';
}

// ESVを数値またはシンボルで指定して数値を得る
function getESVbyte(v) {
    if (typeof v == 'string') {
        for (let it in ESV) {
            if (it == v) {
                return ESV[it];
            }
        }
        // 定義されていないESVシンボルを指定した
        throw new Error('Undefined ESV symbol.');
    }
    if (typeof v != 'number') {
        // シンボルでも数値でもない方法でESVを指定した
        throw new Error('Invalid ESV code specification.');
    }
    return v;
}

// プロパティオブジェクトからフレームバッファを作成
function createProperty(p) {
    if (!p.hasOwnProperty('EPC')) {
        // EPCがない
        throw new Error('EPC is not specified.');
    }

    let pdc;
    if (p.hasOwnProperty('PDC')) {
        // PDCの指定があればそれを採用
        pdc = p.PDC;
    } else if (p.hasOwnProperty('EDT')) {
        // PDCの指定がなければEDTの長さを採用
        if (typeof p.EDT == 'number') {
            // EDT: XX の形式
            pdc = 1;
            p.EDT = [p.EDT];
        } else {
            // EDT: [XX YY] の形式
            pdc = p.EDT.length;
        }
    } else {
        // PDCもEDTもなければPDCは0とする
        pdc = 0;
    }

    // EPC,PDC
    let prop = [Buffer.from([p.EPC, pdc])];
    if (pdc > 0) {
        // EDT...
        prop.push(Buffer.from(p.EDT));
    }

    return Buffer.concat(prop);
}

// 指定数値を指定桁数の16進数文字列に変換する
function toHexString(v, c) {
    return ('00000000' + v.toString(16)).slice(-c);
}

// コールバック用キーをTIDから作成
function makeKey(tid) {
    return 'K' + tid.toString();
}

// 成功するまでaddMembershipを繰り返す
function tryAddMembership(self, client, address) {
    try {
        client.addMembership(address);
        // addMembershipが成功したらサブネット検索
        setTimeout(searchNode, 1000, self);
    } catch (e) {
        setTimeout(function () {tryAddMembership(self, client, address);}, 5000);
    }
}

// フレーム解析
function parseFrame(b) {
    if (b.length < 14) {
        // フレームが短すぎる
        throw new Error('parseFrame: too short frame length.');
    }
    const esv = getESVsymbol(b[10]);
    if (esv == '?') {
        // 不正なESV
        throw new Error(`parseFrame: invalid ESV code(${toHexString(b[10], 2)}).`);
    }
    // プロパティは特殊な形式のものがあるため、下手に解析せずそのままPROPとして切り出す
    return {
        EHD:  b.readUIntBE(0, 2),
        TID:  b.readUIntBE(2, 2),
        SEOJ: b.readUIntBE(4, 3),
        DEOJ: b.readUIntBE(7, 3),
        ESV:  esv,
        OPC:  b[11],
        PROP: b.slice(12)
    };
}

// フレームを表示可能な文字列に変換
function toString(f) {
    let s = 
    '{ EHD:' + toHexString(f.EHD,  4) +
    ' TID:'  + toHexString(f.TID,  4) +
    ' SEOJ:' + toHexString(f.SEOJ, 6) +
    ' DEOJ:' + toHexString(f.DEOJ, 6) +
    ' ESV:'  + f.ESV +
    ' OPC:'  + toHexString(f.OPC,  2) +
    ' PROP:' + f.PROP.toString('hex') +
    ' }';
    return s;
}

// TIDの生成とコールバック、タイムアウトの設定
function generateTID(self, callback, timeout, pa) {
    let tid = (self.tid + 1) % 0x10000;
    self.tid = tid;
    if (callback !== undefined && timeout !== undefined) {
        let key = makeKey(tid);
        self.cblist[key] = {
            func:  callback,
            pa:    pa,
            timer: setTimeout((self, key) => {
                // タイムアウト処理
                if (self.cblist.hasOwnProperty(key)) {
                    if (typeof(self.cblist[key].func) == 'function') {
                        self.cblist[key].func({error:'timeout'}, self.cblist[key].pa);
                    }
                    delete self.cblist[key];
                }
            }, timeout, self, key)
        };
    }
    return tid;
}

// フレームオブジェクトからフレームバッファを作成
// フレームオブジェクト：
// {
//     SEOJ: 0x123456,
//     DEOJ: 0xfedcba,
//     ESV:  0x60 or 'SetC', <= 数値もしくはシンボル
//
//     プロパティが1つの場合(形式1)
//     EPC:  0x80,           <= 直接EPC/PDC/EDTを書いてもよい
//     PDC:  0x01,           <= PDCは省略可（EDTから自動で計算できる）
//     EDT:  0x30            <= EDTも省略可
//
//     または(形式2)
//     PROP: {
//         EPC:  0x80,       <= PROCオブジェクトにEPC/PDC/EDTを書いてもよい
//         EDT:  0x30
//     }
//
//     プロパティが2つ以上ある場合は(形式3)
//     PROP: [
//         {
//             EPC: 0xFA,
//             PDC: 0x02,
//             EDT: [0x30, 0x31]  <= 配列でも可
//         },
//         {
//             EPC: 0xFB,
//             PDC: 0x03,
//             EDT: [0x30, 0x31, 0x32]
//         },
//     ]
// }
//
function createFrame(self, f, callback, timeout, pa) {
    // ヘッダ作成(EHD～OPC)
    let header = Buffer.allocUnsafe(12);
    let tid = generateTID(self, callback, timeout, pa);
    header.writeUIntBE(EHD, 0, 2);              // EHD
    header.writeUIntBE(tid, 2, 2);              // TID
    header.writeUIntBE(f.SEOJ, 4, 3);           // SEOJ
    header.writeUIntBE(f.DEOJ, 7, 3);           // DEOJ
    header[10] = getESVbyte(f.ESV);             // ESV

    let pool = [header];
    if (f.hasOwnProperty('EPC')) {
        // 形式1
        header[11] = 1;                         // OPC
        pool.push(createProperty(f));
    } else if (!Array.isArray(f.PROP)) {
        // 形式2
        header[11] = 1;                         // OPC
        pool.push(createProperty(f.PROP));
    } else {
        // 形式3
        header[11] = f.PROP.length;             // OPC
        for (let i = 0; i < f.PROP.length; i++) {
            pool.push(createProperty(f.PROP[i]));
        }
    }

    return Buffer.concat(pool);
}

// フレーム送信
function send(address, buf) {
    let client = dgram.createSocket('udp4');
    debug(`send ${address} ${toString(parseFrame(buf))}`);
    client.send(buf, 0, buf.length, PORT, address, () => {
        client.close();
    });
}

// 初期化
// callback: グローバルコールバック。要求送信固有のコールバックで処理できないメッセージを処理する。
// cfg: 動作設定(下記コメント参照)
var el = function(callback, cfg) {
    // TID
    this.tid = 0;
    // TIDに関連付けたコールバック
    this.cblist = [];
    // マルチキャストアドレス
    this.multicastAddress = multicastAddress;
    // グローバルコールバック
    this.callback = callback;
    // ESV
    this.ESV = ESV;
    // ノード
    this.elnode = {};
    // クラスインスタンス
    this.NODEPROFILE = NODEPROFILE;
    this.CONTROLLER  = CONTROLLER;
    // 動作設定
    this.cfg = Object.assign({
        RETRYCOUNT:     4,      // 要求リトライ回数
        RETRYINTERVAL:  1000,   // 要求リトライ間隔(ms)
        QUERYTIMEOUT:   3000,   // 要求タイムアウト(ms)
        NORESINTERVAL:  1000,   // 応答不要要求間隔(ms) 少し待つ
        NOTIFYINTERVAL: 0,      // 通知/応答間隔(ms)    待たない
        SEARCHTYPE:     0       // ノードサーチ方法(0=マルチキャスト/1=ユニキャスト)
    }, cfg);

    var client = dgram.createSocket('udp4');

    // マルチキャスト送信用ノード作成
    updateNode(this, multicastAddress, 'address', multicastAddress);

    // マルチキャストを待ち受ける
    client.on('listening', () => {
        client.setMulticastLoopback(true);
        tryAddMembership(this, client, multicastAddress);
    });

    // フレーム受信
    client.on('message', (message, remote) => {
        // 受信フレーム処理
        let frame;
        try {
            frame = parseFrame(message);
        } catch (e) {
            // フレーム異常
            console.error('el: incomming: ' + e.message);
            return;
        }

        if (frame.PROP[0] == 0x83 && (frame.ESV == 'INF' || frame.ESV == 'Get_Res')) {
            // ノード検出
            if (frame.PROP[1] != 17 || frame.PROP.length < (17+2)) {
                // 17バイト形式以外は未サポート
                console.error(`el: incomming: ${remote.address} unsupport ESV(83) length ${frame.PROP[1]}`);
                return;
            }
            let node = '';
            for (let i = 0; i < 17; i++) {
                node += toHexString(frame.PROP[i + 2], 2);
            }
            updateNode(this, node, 'address', remote.address);
        }

        // フレームが解析できてEHDが正当ならコールバック
        debug(`el: incomming: ${remote.address} ${toString(frame)}`);
        let key = makeKey(frame.TID);
        let par = {frame:frame, rinfo:remote};
        par.node = getAddressNode(this, remote.address);

        if (this.cblist.hasOwnProperty(key)) {
            // TIDに関連付いたコールバックがあれば呼ぶ
            if (this.cblist[key].func(par, this.cblist[key].pa) == true) {
                // タイムアウトタイマー、コールバック削除
                clearTimeout(this.cblist[key].timer);
                delete this.cblist[key];
            }
        } else {
            // TIDに関連付いたコールバックがなければグローバルなコールバックを呼ぶ
            if (frame.ESV == 'INF' || frame.ESV == 'Get_Res') {
                goCallback(par.node, par, this.callback);
            }
        }

        if (frame.SEOJ    == NODEPROFILE &&
            frame.DEOJ    == NODEPROFILE &&
            frame.ESV     == 'INF' &&
            frame.PROP[0] == 0xd5) {
            // echonet-lite機器が新たに起動したか、アドレスが変更になった？
            searchNode(this);
        }
    });

    // 待ち受けポート設定
    client.bind(PORT);
};

// 任意要求送信
// node/instanceに対して指定した要求を送信する
//
// node: 送信先ノードの識別番号(EPC83の値) 例)'fe00007700000000000000000000000001'
//       または el.multicastAddress でマルチキャスト送信
// instance: 送信先インスタンス 例)0x0ef001
// esv: 要求タイプ 例)el.ESV.Get
// epc: プロパティコード 例)0x80
// edt: データ 例)0x30
// callback: コールバック関数(指定しない場合はグローバルコールバックが呼ばれる)
el.prototype.sendtonode = function(node, instance, esv, epc, edt, callback) {
    let frame = {
        SEOJ: CONTROLLER,
        DEOJ: instance,
        ESV:  esv,
        EPC:  epc,
        EDT:  edt,
        callback: callback
    };
    frame.buf = createFrame(this, frame);
    pushExec(this, node, frame);
}

// SetC要求送信
el.prototype.set = function(node, instance, epc, edt, callback) {
    this.sendtonode(node, instance, ESV.SetC, epc, edt, callback);
};

// Get要求送信
el.prototype.get = function(node, instance, epc, callback) {
    this.sendtonode(node, instance, ESV.Get, epc, [], callback);
};

// 要求キュークリア
el.prototype.clearQue = function(node) {
    this.elnode[node].que = [];
};

module.exports = el;
