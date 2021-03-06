# alt-echonet-lite

ラズパイなどで簡易にECHONET-Lite機器をコントロールするためのモジュールです。
本モジュールには下記のような特徴があります。

* 制御対象機器をIPアドレスではなく識別番号(EPC83)で指定する
* Set/Getのエラーリトライを自動で行ってくれる

IPアドレスがDHCPで割当てされ、何かの拍子に変わってしまう環境であったり、426/429/920MHz帯無線（パナソニック社製アドバンス照明などに使用されてます）などを使用していて通信リトライがないと話にならない環境（つまりわが家です）には必要な機能ですが、なぜだかこういったフリーな実装をみないので実装しました。

EPC83の識別番号は付属の sample-search.js を実行することでローカルネットワークにあるECHONET-Lite機器のものを表示することができます。

## 使い方
本モジュールを読み込んで下記のような感じで使用します。

### 初期化
```JavaScript
const el_factory = require('alt-echonet-lite');

el = new el_factory((info) => {
    // グローバルコールバック
    // get/setでコールバックを指定しない場合は、こちらにコールバックします
    console.log(info);
    const node = 'fe00007700000000000000000000000001';
    if (info.EPC == 0x83 && info.node == node) {
        // EPC83でのノード検索完了
    }
});
```

### Set/Get
```JavaScript
const node = 'fe00007700000000000000000000000001';
const instance = 0x029101; // 単機能照明
const epc = 0x80;
const esv = 0x30;

// 指定nodeのインスタンス029101の照明をONする
// コールバックを指定していないので結果はグローバルコールバックする
el.set(node, instance, epc, esv);

// 指定nodeのインスタンス029101の照明の状態を取得する
// このようにget/setで個別コールバックすることも可
el.get(node, instance, epc, (info) => {
    console.log(info);
});

// 全インスタンスの結果を1つの個別コールバックですべて受けることができる
const all_instance = 0x029100;
el.get(node, all_instance, epc, (info) => {
    console.log(info);
});

// 同報要求の結果を1つの個別コールバックですべて受けることができる
el.get(el.multicastAddress, instance, epc, (info) => {
    console.log(info);
});

// 複数のEPCのset/getができる
el.get(node, instance, {0x80, 0xb0}) (info) => {
    console.log(info);
});
el.get(node, instance, [0x80, 0xb0]) (info) => {
    console.log(info);
});
el.set(node, instance, {0x80:0x30, 0xb0:0x40}, info => {
    console.log(info);
})

```

### コールバック
コールバックは、モジュール初期化のnew時に渡すグローバルコールバックと、各get/setで渡す個別コールバックがあります。

いずれのコールバックでも下記のようなオブジェクトを受け取ります。
コールバックは1つのEPCごとに行われますので、2つ以上のEPCが含まれた結果の場合、その回数にわけて1つずつコールバックされます。

また、マルチキャストや全インスタンス宛ての要求でのコールバックはタイムアウトするまでに受け取ったすべての応答についてコールバックされます。

```JavaScript
var info = {
    node: 'fe00007700000000000000000000000001', // 送信元識別番号
    instance: 0x029101,                         // 送信元インスタンス
    ESV: 'Get_Res',                             // ESV
    EPC: 0x83,                                  // EPC
    PDC: 17,                                    // PDC
    EDT: [254, 0, 0, ...],                      // EDT
    rinfo: {
        address: '192.168.x.x'                  // 送信元アドレス
    }
};
```
モジュールは、起動後自動で機器を探索(EPC83のget)にいきますので、機器が返した応答はグローバルコールバックで受け取れます。

エラーの場合は、下記のようなオブジェクトを受け取ります。
```JavaScript
var info = {
    node: 'fe00007700000000000000000000000001', // 送信元識別番号
    error: 'timeout'                            // エラー
};
```

## 使用環境
以下のような環境で使用しています。

|項目|内容|
|:----|:--------------------------------------|
|ホスト|Raspberry Pi 3B+ Raspbian Stretch Lite|
|ECHONET-Lite機器|パナソニック社製アドバンスリンクモデル x 2系統|
||パナソニック社製IP/JEM-A変換アダプタ HF-JA1-W|
||パナソニック社製AiSEG2|
||大阪ガス社製エネファーム 191-PA09|
||シャープ社製空気清浄機 KI-WF75|
