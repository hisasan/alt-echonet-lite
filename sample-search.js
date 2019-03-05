'use strict';

const el_fct = require('./');

// 機器探索を行って、下記のように出力します。
//┌────────────────────────────────────┬─────────────────┬─────────────────────────────────────────────────────────────────────────────────────────────────────┐
//│              (index)               │     address     │                                              instance                                               │
//├────────────────────────────────────┼─────────────────┼─────────────────────────────────────────────────────────────────────────────────────────────────────┤
//│ fe00000xxxxxxxxxxxxxxxxxxxxxxxxxxx │ '192.168.3.35'  │                                              '05fd01'                                               │
//│ fe00000yyyyyyyyyyyyyyyyyyyyyyyyyyy │ '192.168.3.29'  │ '0f2001,029101,029102,029103,029104,029105,029106,029107,029108,029109,02910a,02910b,02910c,02910d' │
//│ fe00000zzzzzzzzzzzzzzzzzzzzzzzzzzz │ '192.168.3.39'  │        '0f2001,029101,029102,029103,029104,029105,029106,029107,029108,029109,02910a,02910b'        │
//│ fe00000aaaaaaaaaaaaaaaaaaaaaaaaaaa │ '192.168.3.40'  │                                              '027c01'                                               │
//│ fe00000bbbbbbbbbbbbbbbbbbbbbbbbbbb │ '192.168.3.18'  │                                              '013501'                                               │
//│ fe00000ccccccccccccccccccccccccccc │ '192.168.3.216' │                                              '05ff01'                                               │
//└────────────────────────────────────┴─────────────────┴─────────────────────────────────────────────────────────────────────────────────────────────────────┘

let elnode = {};

function toHexString(n, l) {
	// 文字列0をつなげて，後ろからl文字分スライスする
    return (('0000000' + n.toString(16)).slice(-l));
}

function log(info) {
    let s = '';
    for (let i = 0; i < info.PDC; i++) {
        s += toHexString(info.EDT[i], 2);
    }
    console.log(`address=${info.rinfo.address} instance=${toHexString(info.instance, 6)} EPC=${toHexString(info.EPC, 2)} PDC=${info.PDC} EDT=${s}`);
}

function updateNode(node, a) {
    if (!elnode.hasOwnProperty(node)) {
        elnode[node] = {};
    }
    elnode[node].address = a;
}

var endTimer = null;
var el = new el_fct((info) => {
    if (info.hasOwnProperty('error')) {
        // エラーコールバックは無視
        return;
    }
    console.log(info);
    if (info.EPC == 0x83) {
        updateNode(info.node, info.rinfo.address);
        // 探索ノードのインスタンスリストを取得する
        el.get(info.node, el.NODEPROFILE, 0xd6, (info) => {
            if (info.hasOwnProperty('error')) {
                return;
            }
            // インスタンスリスト追加
            let ilist  = '';
            let icount = info.EDT[0];
            let iedt   = 1;
            for (let i = 0; i < icount; i++) {
                if (i > 0) { ilist += ','; }
                for (let j = 0; j < 3 && iedt < info.EDT.length; j++) {
                    ilist += toHexString(info.EDT[iedt++], 2);
                }
            }
            updateNode(info.node, info.rinfo.address);
            elnode[info.node].instance = ilist;
            if (endTimer != null) {
                clearTimeout(endTimer);
            }
            // 3秒以上、機器からの応答がなければ探索終了
            endTimer = setTimeout(() => {
                console.table(elnode);
                process.exit(0);
            }, 3000);
        });
    } else {
        log(info);
    }
}, {SEARCHTYPE:1});
