"""Every word the window says, in the language it says it in.

Three languages, and the rule that shapes this file: **a language shows only its own words.**
Nothing here is bilingual side by side. What may appear from another script is a *mention* -- a
product name, a path, a version -- and a mention is rendered in that script's own font rather than
in the surrounding one, which is what `split_scripts` in the window is for.

The Japanese is written to keep katakana and Latin down, as asked. Where a native word exists it is
used: 時刻認証 rather than タイムスタンプ, 覚え書き rather than メモ, 実行前の確認 rather than ドライラン,
成果物 rather than アーティファクト. What remains is what has no reasonable alternative in a
software window -- ファイル, プロジェクト, ソフト -- and no more of it than that.
"""

from __future__ import annotations

import os

LANGUAGES = ("zh", "en", "ja")
DEFAULT_LANGUAGE = "zh"

# Each language in its own words, which is the only honest way to offer a language list: somebody who
# cannot read the current interface still has to be able to find their own.
LANGUAGE_NAMES = {"zh": "中文", "en": "English", "ja": "日本語"}

# Which font draws which script. Two per language, because the request was two per language:
# Chinese in 宋体 with Latin in Times New Roman; Japanese in 明朝体 with Latin in ゴシック体.
# 明朝体 here is Yu Mincho rather than MS Mincho -- both are installed, and MS Mincho is a bitmap-era
# face that looks rough beside the rest of the desktop.
FONTS = {
    "zh": {"han": "SimSun", "latin": "Times New Roman"},
    "en": {"han": "SimSun", "latin": "Times New Roman"},
    "ja": {"han": "Yu Mincho", "latin": "Yu Gothic"},
}

FONT_SIZE = 10

# The notice's mark is a drawing made of characters, so it is the one place where the font is chosen
# for geometry rather than for script: if the cells are not all the same width the shape leans. Each
# of these is a fixed-pitch face from the same family the language already uses -- 宋体's monospaced
# sibling for Chinese, a ゴシック体 for Japanese -- so nothing new is introduced by needing one.
ART_FONT = {"zh": "SimSun", "en": "Consolas", "ja": "MS Gothic"}

# How to say each language's own name of its own font, for the About window.
FONT_NOTE = {
    "zh": "中文 宋体  ·  西文 Times New Roman",
    "en": "Chinese SimSun  ·  Latin Times New Roman",
    "ja": "日本語 明朝体  ·  英数 ゴシック体",
}

STRINGS: dict[str, dict[str, str]] = {
    # window and menus
    "app.name": {"zh": "独家签署", "en": "OnlySign", "ja": "オンリーサイン"},
    "menu.file": {"zh": "文件", "en": "File", "ja": "ファイル"},
    "menu.settings": {"zh": "设置", "en": "Settings", "ja": "設定"},
    "menu.language": {"zh": "语言", "en": "Language", "ja": "言語"},
    "menu.about": {"zh": "关于", "en": "About", "ja": "このソフトについて"},
    "menu.exit": {"zh": "退出", "en": "Exit", "ja": "終了"},
    "menu.scan": {"zh": "扫描产物", "en": "Scan for artifacts", "ja": "候補を探す"},
    "menu.dryrun": {"zh": "干跑", "en": "Dry run", "ja": "実行前の確認"},
    "menu.execute": {"zh": "执行签名", "en": "Execute signing", "ja": "署名を実行"},
    "menu.check": {"zh": "对账", "en": "Check the ledger", "ja": "記録を照合"},
    "menu.open_ledger": {"zh": "打开记录所在目录", "en": "Open the folder with the record",
                         "ja": "記録のある場所を開く"},

    # artifacts
    "group.artifacts": {"zh": "产物来源", "en": "Artifacts", "ja": "成果物の場所"},
    "field.project": {"zh": "项目目录", "en": "Project directory", "ja": "プロジェクトの場所"},
    "field.artifact_dir": {"zh": "产物目录", "en": "Artifact directory", "ja": "成果物の場所"},
    "button.browse": {"zh": "浏览", "en": "Browse", "ja": "選ぶ"},
    "button.scan": {"zh": "扫描", "en": "Scan", "ja": "探す"},
    "group.proposed": {
        "zh": "候选产物（默认全部勾选；你不按按钮就不会签任何东西）",
        "en": "Proposed (nothing is signed until you press a button)",
        "ja": "候補（はじめから全部に印が付いています。押さない限り何も署名しません）"},
    "col.sign": {"zh": "签名", "en": "sign", "ja": "署名"},
    "col.file": {"zh": "文件", "en": "file", "ja": "名前"},
    "col.kind": {"zh": "类型", "en": "type", "ja": "種類"},
    "col.size": {"zh": "字节", "en": "bytes", "ja": "大きさ"},
    "col.state": {"zh": "状态", "en": "state", "ja": "状態"},
    "col.why": {"zh": "为什么在这里", "en": "why it is here", "ja": "ここにある理由"},
    "button.select_all": {"zh": "全选", "en": "Select all", "ja": "すべて選ぶ"},
    "button.select_none": {"zh": "全不选", "en": "Select none", "ja": "一つも選ばない"},

    # certificate
    "group.certificate": {"zh": "证书", "en": "Certificate", "ja": "証明書"},
    "button.refresh": {"zh": "刷新", "en": "Refresh", "ja": "更新"},
    "button.make_cert": {"zh": "新建自签证书…", "en": "Make a self-signed one...",
                         "ja": "自己署名の証明書を作る…"},
    "cert.choose": {"zh": "请先选一张证书。", "en": "Choose a certificate first.",
                    "ja": "先に証明書を選んでください。"},
    "cert.choose_files": {"zh": "请先扫描，或至少勾选一个要签名的文件。",
                          "en": "Scan a project, or mark at least one file to sign.",
                          "ja": "先に調べるか、署名するファイルに少なくとも一つ印を付けてください。"},
    "cert.none": {"zh": "这里没有能签名的证书。可以新建一张自签证书，或导入一张。",
                  "en": "Nothing here can sign. Make a self-signed certificate, or import one.",
                  "ja": "ここには署名できる証明書がありません。自己署名の証明書を作るか、取り込んでください。"},
    "cert.expires": {"zh": "还剩 {days} 天", "en": "{days} days left", "ja": "残り {days} 日"},
    "cert.self_signed": {"zh": "自签名", "en": "self-signed", "ja": "自己署名"},
    "cert.issued_by": {"zh": "签发者 {issuer}", "en": "issued by {issuer}", "ja": "発行元 {issuer}"},

    # signing
    "group.signing": {"zh": "签名", "en": "Signing", "ja": "署名"},
    "field.note": {"zh": "备注", "en": "Note", "ja": "覚え書き"},
    "field.copy_to": {"zh": "签名副本复制到", "en": "Copy signed files to", "ja": "署名済みの複製先"},
    "field.record": {"zh": "签名记录保存到", "en": "Where the record is kept", "ja": "署名の記録先"},
    "field.authorities": {"zh": "时间戳服务器，按顺序尝试", "en": "Timestamp authorities, in order",
                          "ja": "時刻認証の提供元（上から順に試します）"},
    "check.untimestamped": {
        "zh": "接受没有时间戳的签名（证书到期后就无法再验证）",
        "en": "Accept a signature with no timestamp (it stops verifying when the certificate expires)",
        "ja": "時刻認証のない署名を受け入れる（証明書が切れると確かめられなくなります）"},
    "check.force": {
        "zh": "签一个已经带签名的文件（会追加第二个签名）",
        "en": "Sign a file that already carries a signature (appends a second one)",
        "ja": "すでに署名のあるファイルに署名する（二つ目の署名が付きます）"},

    # trust
    "group.trust": {"zh": "本机信任（信任不随产物走）", "en": "Trust on this machine (it does not travel)",
                    "ja": "この端末での信頼（成果物には付いて行きません）"},
    "trust.none": {"zh": "不动", "en": "leave it alone", "ja": "何もしない"},
    "trust.user_publishers": {"zh": "本账户·发布者", "en": "this account: publisher",
                              "ja": "この利用者：発行元"},
    "trust.user_root": {"zh": "本账户·根", "en": "this account: root", "ja": "この利用者：根"},
    "trust.user_both": {"zh": "本账户·两者", "en": "this account: both", "ja": "この利用者：両方"},
    "trust.machine_both": {"zh": "所有账户·两者", "en": "every account: both",
                           "ja": "すべての利用者：両方"},
    "trust.none.why": {"zh": "两个信任库都不动",
                       "en": "leave the trust stores alone",
                       "ja": "どちらの信頼の保管庫も触りません"},
    "trust.user_publishers.why": {
        "zh": "本账户：只是关于发布者的一句声明，不改变任何判定结果",
        "en": "this account: a statement about the publisher, which changes no verdict",
        "ja": "この利用者：発行元についての覚え書きで、判定は変わりません"},
    "trust.user_root.why": {
        "zh": "本账户：信任锚，装了之后签名在这台机器上才算通过（Windows 会问一次）",
        "en": "this account: the trust anchor, so signatures verify here (Windows asks once)",
        "ja": "この利用者：信頼の根。これを入れて初めてこの端末で通ります（一度だけ確認が出ます）"},
    "trust.user_both.why": {
        "zh": "本账户：两个库都装，弹窗要问的就是这个",
        "en": "this account: both stores, which is what the prompt is for",
        "ja": "この利用者：両方の保管庫に入れます。確認が出るのはこのためです"},
    "trust.machine_both.why": {
        "zh": "本机所有账户：两个库都装，需要管理员会话",
        "en": "every account on this machine: both stores, needs an elevated session",
        "ja": "この端末のすべての利用者：両方の保管庫に入れます。管理者として実行が必要です"},

    # actions and result
    "button.dry_run": {"zh": "干跑", "en": "Dry run", "ja": "実行前の確認"},
    "button.execute": {"zh": "执行签名", "en": "Execute signing", "ja": "署名を実行"},
    "button.check": {"zh": "对账", "en": "Check the ledger", "ja": "記録を照合"},
    "status.ready": {"zh": "就绪", "en": "ready", "ja": "待機中"},
    "status.working": {"zh": "工作中…", "en": "working...", "ja": "実行中…"},
    "group.result": {"zh": "结果", "en": "Result", "ja": "結果"},

    # what the window itself reports
    "say.scanning": {"zh": "正在扫描 {where} …", "en": "scanning {where} ...", "ja": "{where} を調べています…"},
    "say.found": {"zh": "看了 {examined} 个文件，找到 {count} 个产物",
                  "en": "found {count} artifact(s) after looking at {examined} file(s)",
                  "ja": "{examined} 個のファイルを見て、{count} 個の成果物が見つかりました"},
    "say.note": {"zh": "说明：{text}", "en": "note: {text}", "ja": "説明：{text}"},
    "say.dry_run_heading": {"zh": "干跑 —— 不会碰任何东西：", "en": "dry run -- nothing will be touched:",
                            "ja": "実行前の確認 —— 何も変わりません："},
    "say.signing_heading": {"zh": "正在签名：", "en": "signing:", "ja": "署名しています："},
    "say.ledger": {"zh": "记录：{path}", "en": "ledger: {path}", "ja": "記録：{path}"},
    "say.checking": {"zh": "正在核对 {path} …", "en": "checking {path} ...", "ja": "{path} を照合しています…"},
    "say.scan_failed": {"zh": "扫描失败：{error}", "en": "the scan failed: {error}", "ja": "調べられませんでした：{error}"},
    "say.sign_failed": {"zh": "签名失败：{error}", "en": "the run failed: {error}", "ja": "署名できませんでした：{error}"},
    "say.check_failed": {"zh": "对账失败：{error}", "en": "the check failed: {error}", "ja": "照合できませんでした：{error}"},
    "say.cert_failed": {"zh": "读不到证书库：{error}", "en": "could not read the certificate store: {error}",
                        "ja": "証明書の保管庫を読めません：{error}"},
    "say.preview_failed": {"zh": "预览失败：{error}", "en": "the preview failed: {error}",
                           "ja": "下見に失敗しました：{error}"},
    "say.make_failed": {"zh": "证书没有建成：{error}", "en": "the certificate was not made: {error}",
                        "ja": "証明書を作れませんでした：{error}"},
    "say.made": {"zh": "已生成 {subject}", "en": "made {subject}", "ja": "{subject} を作りました"},
    "say.public_half": {"zh": "  公开的一半：{path}（这个可以发布）",
                        "en": "  public half : {path}  (publish this)",
                        "ja": "  公開する半分：{path}（これは配って構いません）"},
    "say.private_half": {"zh": "  私钥一半：{path}（绝不外传）",
                         "en": "  private key : {path}  (never publish this)",
                         "ja": "  秘密の半分：{path}（絶対に配らないでください）"},
    "say.password": {"zh": "  口令：{password}", "en": "  password    : {password}", "ja": "  合言葉：{password}"},
    "say.password_once": {"zh": "口令只显示这一次，不存别处。现在就记下来。",
                          "en": "The password is shown once and stored nowhere. Write it down now.",
                          "ja": "合言葉は一度だけ出ます。どこにも残りません。今すぐ書き留めてください。"},

    # dialogs
    "dialog.confirm.title": {"zh": "确认签名", "en": "Confirm", "ja": "確認"},
    "dialog.confirm.body": {
        "zh": "要用下面这张证书签 {count} 个文件：\n\n  {subject}\n\n记录会写到：\n\n  {ledger}\n\n"
              "签名一旦加上，无法从文件上取下来。",
        "en": "Sign {count} file(s) with:\n\n  {subject}\n\nand record it in:\n\n  {ledger}\n\n"
              "A signature cannot be taken back off a file.",
        "ja": "{count} 個のファイルに、次の証明書で署名します：\n\n  {subject}\n\n記録はここに残ります：\n\n  {ledger}\n\n"
              "一度付いた署名は、ファイルから外せません。"},
    "dialog.make_cert.title": {"zh": "新建自签证书", "en": "A self-signed certificate", "ja": "自己署名の証明書"},
    "dialog.make_cert.question": {"zh": "证书要写明它是做什么用的？", "en": "What should the certificate say it is for?",
                                  "ja": "何のための証明書かを書き込みます。表示する名前は？"},
    "dialog.make_cert.explain": {
        "zh": "任何检查你签名文件的人都会看到这句话。",
        "en": "This is shown to anyone who inspects a file you sign.",
        "ja": "あなたが署名したファイルを調べた人に、この文字が見えます。"},
    "dialog.make_cert.years": {"zh": "有效期（年）", "en": "Valid for (years)", "ja": "有効期間（年）"},
    "dialog.make_cert.where": {"zh": "证书文件写到哪里", "en": "Where to write the certificate files",
                               "ja": "証明書のファイルをどこに書きますか"},
    "dialog.make_cert.create": {"zh": "创建", "en": "Create", "ja": "作る"},

    # file dialogs
    "pick.project": {"zh": "项目目录", "en": "The project directory", "ja": "プロジェクトの場所"},
    "pick.artifacts": {"zh": "产物所在的目录", "en": "The directory the artifacts are in",
                       "ja": "成果物のある場所"},
    "pick.output": {"zh": "签名副本复制到哪里", "en": "Where signed copies should go",
                    "ja": "署名済みの複製をどこに置きますか"},
    "pick.ledger": {"zh": "签名记录保存在哪里", "en": "Where the record is kept",
                    "ja": "署名の記録をどこに残しますか"},

    # about
    "about.title": {"zh": "关于独家签署", "en": "About OnlySign", "ja": "オンリーサインについて"},
    "about.purpose": {
        "zh": "给本地产物签名，并且日后说得出「当初签的是哪一份」。\n"
              "引擎与命令行是同一套；窗口只负责画出来。",
        "en": "Sign local build artifacts, and be able to say later which build was signed.\n"
              "The engine and the command line are one implementation; the window only draws it.",
        "ja": "手元の成果物に署名し、あとから「あのとき署名したのはどれか」を言えるようにします。\n"
              "中身と命令行は同じもので、この窓はそれを描いているだけです。"},
    "about.close": {"zh": "关闭", "en": "Close", "ja": "閉じる"},

    # why a candidate was proposed, and what the scan noticed. The engine carries the same reasons
    # as codes for exactly this: the strings it prints are English because a script reads them.
    "why.given": {"zh": "它在您指定的目录里", "en": "it is in the directory you named",
                  "ja": "指定した場所にあります"},
    "why.output_directory": {"zh": "它在一个名为「{name}」的目录里",
                             "en": "it is in a directory named '{name}'",
                             "ja": "「{name}」という名前の場所にあります"},
    "why.build_config": {"zh": "{file} 里写着产物是 {declared}",
                         "en": "{file} says the output is {declared}",
                         "ja": "{file} に成果物は {declared} と書かれています"},
    "why.library": {"zh": "这台机器已经记录过它（{name}）",
                    "en": "this machine has already recorded it ({name})",
                    "ja": "この端末がすでに記録しています（{name}）"},
    "note.artifact_dir_missing": {"zh": "您指定的产物目录不存在：{path}",
                                  "en": "the artifact directory you named does not exist: {path}",
                                  "ja": "指定した成果物の場所がありません：{path}"},
    "note.declared_empty": {"zh": "{file} 里写着产物在「{declared}」，但那里没有能签名的东西",
                            "en": "{file} says the output is '{declared}', and there is nothing "
                                  "signable there",
                            "ja": "{file} には成果物が「{declared}」とありますが、"
                                  "そこに署名できるものはありません"},
    "note.truncated": {"zh": "候选太多，只列到 {count} 个",
                       "en": "stopped at {count} candidates",
                       "ja": "候補が多いため {count} 件で打ち切りました"},
    "note.nothing_signable": {"zh": "没有找到能签名的东西。如果项目还没构建，请先构建，"
                                    "或者直接指定产物所在的目录。",
                              "en": "nothing signable was found. If the project has not been built "
                                    "yet, build it first, or name the directory the artifacts land in.",
                              "ja": "署名できるものが見つかりません。まだ組み立てていない場合は"
                                    "先に組み立てるか、成果物のある場所を指定してください。"},

    "tab.artifacts": {"zh": "产物", "en": "Artifacts", "ja": "成果物"},
    "tab.signing": {"zh": "签名设置", "en": "Signing", "ja": "署名の設定"},
    "tab.trust": {"zh": "本机信任", "en": "Trust", "ja": "この端末の信頼"},
    "tab.mark": {"zh": "标记", "en": "Mark", "ja": "印"},

    # marking: for the formats that have nowhere to sign. The window decides nothing here either --
    # which carrier applies is asked of the same function the command line asks.
    "group.mark_target": {"zh": "打标记的对象", "en": "What to mark", "ja": "印を打つ相手"},
    "field.mark_file": {"zh": "文件", "en": "File", "ja": "ファイル"},
    "field.mark_identity": {"zh": "身份文件（写明标记归属谁）",
                            "en": "Identity file (naming who the mark belongs to)",
                            "ja": "発行元のファイル（印が誰のものかを書いたもの）"},
    "field.mark_year": {"zh": "年份（可留空）", "en": "Year (may be left empty)", "ja": "年（空でも構いません）"},
    "pick.mark_file": {"zh": "要打标记的文件", "en": "The file to mark", "ja": "印を打つファイル"},
    "pick.mark_identity": {"zh": "写明标记归属的身份文件",
                           "en": "The identity file naming who the mark belongs to",
                           "ja": "印が誰のものかを書いたファイル"},
    "pick.mark_out": {"zh": "写到哪里", "en": "Where to write it", "ja": "どこに書きますか"},
    "button.preview": {"zh": "预览", "en": "Preview", "ja": "下見"},
    "button.place": {"zh": "打标记", "en": "Place the mark", "ja": "印を打つ"},
    "button.read_mark": {"zh": "读回标记", "en": "Read the mark back", "ja": "印を読み直す"},
    "mark.what_it_is": {
        "zh": "标记不需要密码学，只需要一个日后还在的地方。它说的是「这是谁的」，"
              "签名说的是「谁为这些字节作保」。有签名槽位的格式要签名，不打标记。",
        "en": "A mark needs no cryptography, only somewhere the text will still be later. It answers "
              "who says this is theirs; a signature answers who vouches for these bytes. A format "
              "with a signature slot is signed, not marked.",
        "ja": "印に暗号はいりません。あとになっても残る場所があれば足ります。印は「これは誰のものか」を、"
              "署名は「このバイトを誰が保証するか」を答えます。署名を入れる場所のある形には署名し、印は打ちません。"},

    "group.boot": {"zh": "引导扇区（没有文件可标记时）",
                   "en": "A boot sector (when there is no file to mark)",
                   "ja": "起動の記録（印を打つファイルが無いとき）"},
    "field.boot_out": {"zh": "写到", "en": "Write to", "ja": "書き出し先"},
    "button.build_sector": {"zh": "做一个 512 字节的扇区", "en": "Build a 512-byte sector",
                            "ja": "512 バイトの記録を作る"},
    "button.build_floppy": {"zh": "做一个 1.44 MB 软盘映像", "en": "Build a 1.44 MB floppy image",
                            "ja": "1.44 MB の記録を作る"},
    "boot.why": {
        "zh": "扇区本身就是载体——没有文件可标时，标记就是它的全部内容。",
        "en": "The sector is the carrier itself: with no file to mark, the mark is all there is.",
        "ja": "記録そのものが載せ先です。印を打つファイルが無いときは、印だけが中身になります。"},

    "say.mark_checking": {"zh": "正在看 {where} …", "en": "looking at {where} ...",
                          "ja": "{where} を見ています…"},
    "say.mark_failed": {"zh": "没做成：{error}", "en": "that did not work: {error}",
                        "ja": "できませんでした：{error}"},
    "say.mark_no_identity": {
        "zh": "请先指定身份文件——标记说的就是「这是谁的」，编一个名字是它唯一不能做的事。",
        "en": "Name an identity file first: a mark says whose it is, and inventing a name is the "
              "one thing a mark must not do.",
        "ja": "先に発行元のファイルを指定してください。印は「誰のものか」を言うもので、"
              "名前を作ってしまうことだけはできません。"},
    "say.mark_preview": {"zh": "预览——不会写任何东西：", "en": "preview -- nothing will be written:",
                         "ja": "下見 —— 何も書きません："},
    "say.mark_placed": {"zh": "已打上标记：", "en": "the mark is on:", "ja": "印を打ちました："},
    "say.mark_read": {"zh": "读回的标记：", "en": "what the file says:", "ja": "読み直した印："},
    "say.mark_none": {"zh": "这个文件上没有标记。", "en": "there is no mark on this file.",
                      "ja": "このファイルには印がありません。"},
    "say.mark_unreadable": {
        "zh": "这个格式读不出标记（能打的三种是 zip 的注释、tar 追加的成员、ISO 的应用区）。",
        "en": "this format carries no mark this tool can read (a zip comment, an appended tar "
              "member and an ISO's Application Use field are the three it places).",
        "ja": "この形からは印を読み出せません（印を載せられるのは zip の注記、tar に足す項目、"
              "ISO の応用領域の三つです）。"},
    "say.mark_strength": {"zh": "强度：{strength}", "en": "strength: {strength}", "ja": "強さ：{strength}"},
    "say.mark_carrier": {"zh": "载体：{carrier}", "en": "carrier: {carrier}", "ja": "載せ先：{carrier}"},
    "say.mark_digest": {"zh": "摘要：{digest}", "en": "digest: {digest}", "ja": "要約：{digest}"},
    "say.mark_no_digest": {"zh": "摘要：没有（标记仍然算数，但说明不了文件没被改过）",
                           "en": "digest: none (the mark still stands, but it cannot say the file "
                                 "went unaltered)",
                           "ja": "要約：無し（印は有効ですが、変わっていないことは示せません）"},
    "say.mark_wrote": {"zh": "写下 {size} 字节：{path}", "en": "wrote {size} byte(s): {path}",
                       "ja": "{size} バイトを書き出しました：{path}"},
    "say.mark_agrees": {"zh": "  摘要与文件一致——标记之后没有被动过。",
                        "en": "  the digest agrees with the file -- nothing has touched it since",
                        "ja": "  要約とファイルが一致しています。印のあと何も変わっていません。"},
    "say.mark_disagrees": {"zh": "  摘要对不上——标记之后文件变过。",
                           "en": "  the digest does NOT agree -- the file changed after it was marked",
                           "ja": "  要約が一致しません。印を打ったあとにファイルが変わっています。"},
    "say.mark_boot": {"zh": "扇区做好：{path}（{size} 字节，{what}）",
                      "en": "the sector is built: {path} ({size} bytes, {what})",
                      "ja": "記録を作りました：{path}（{size} バイト、{what}）"},

    # what the window calls a carrier, and why one was refused or is missing. The engine says these
    # in English, in one language, because a script reads that answer; the window says them here.
    "carrier.zip": {"zh": "zip 的注释", "en": "a zip comment", "ja": "zip の注記"},
    "carrier.tar": {"zh": "tar 追加的成员", "en": "an appended tar member", "ja": "tar に足す項目"},
    "carrier.ISO": {"zh": "ISO 的应用区", "en": "an ISO's Application Use field",
                    "ja": "ISO の応用領域"},
    "carrier.boot sector": {"zh": "扇区本身", "en": "the sector itself", "ja": "記録そのもの"},
    "carrier.boot sector in a 1.44 MB image": {
        "zh": "1.44 MB 映像里的扇区", "en": "a sector in a 1.44 MB image",
        "ja": "1.44 MB の記録の中の扇区"},
    "carrier.signed": {"zh": "有签名槽位——该签名，不打标记",
                       "en": "it has a signature slot -- sign it instead",
                       "ja": "署名を入れる場所があります。印ではなく署名をしてください"},
    "carrier.no-carrier": {
        "zh": "这个格式还没有载体（现在能打的是 zip 的注释、tar 追加的成员、ISO 的应用区）",
        "en": "no carrier for this format yet (a zip comment, an appended tar member and an ISO's "
              "Application Use field are the three there are)",
        "ja": "この形にはまだ載せ先がありません（今あるのは zip の注記、tar に足す項目、"
              "ISO の応用領域の三つです）"},
    "mark.strength.hash-record": {
        "zh": "带着摘要，所以它同时说明了「谁主张」和「有没有被动过」",
        "en": "it carries a digest, so it says both who claims it and whether it has been touched",
        "ja": "要約が付いているので、誰のものかと、変わっていないかの両方を示します"},
    "mark.strength.visibility": {
        "zh": "只是可见——谁都能写这几个字节，也没有东西为它作保",
        "en": "visibility only -- anyone can write these bytes and nothing vouches for them",
        "ja": "見えるだけです。誰でもこのバイトを書けますし、保証するものはありません"},
    "mark.strength.boot-sector": {
        "zh": "只是可见——任何东西都能改写这 512 个字节",
        "en": "visibility only -- anything can rewrite these 512 bytes",
        "ja": "見えるだけです。この 512 バイトは何でも書き換えられます"},

    # language menu is listed in its own words
    "lang.current_suffix": {"zh": "（当前）", "en": " (current)", "ja": "（現在）"},

    # what kind of file it is. The engine names these in one language because a script reads that
    # answer; the window says them in its own, from the same value.
    "kind.pe": {"zh": "可执行文件", "en": "a PE image", "ja": "実行できる形"},
    "kind.msi": {"zh": "安装包（MSI）", "en": "an MSI package", "ja": "取り付け用（MSI）"},
    "kind.cab": {"zh": "压缩包（CAB）", "en": "a CAB package", "ja": "詰め合わせ（CAB）"},
    "kind.der": {"zh": "证书文件", "en": "a certificate", "ja": "証明書のファイル"},
    "kind.unknown": {"zh": "认不出来", "en": "not recognised", "ja": "見分けが付きません"},

    # whether it already carries a signature
    "state.signed": {"zh": "已带签名", "en": "signed", "ja": "署名済み"},
    "state.unsigned": {"zh": "未签名", "en": "unsigned", "ja": "未署名"},

    # the preview, said by the window rather than by the engine
    "preview.heading": {"zh": "将要签名（此刻什么都不会发生）：",
                        "en": "about to sign (nothing happens yet):",
                        "ja": "これから署名します（この時点では何も起きません）："},
    "preview.certificate": {"zh": "  证书：{subject}", "en": "  certificate: {subject}",
                            "ja": "  証明書：{subject}"},
    "preview.ledger": {"zh": "  记录写到：{path}", "en": "  recorded in: {path}", "ja": "  記録先：{path}"},
    "preview.timestamps": {"zh": "  时间戳：{authorities}", "en": "  timestamps: {authorities}",
                           "ja": "  時刻認証：{authorities}"},
    "preview.no_timestamps": {"zh": "  时间戳：不要求（证书一到期就无法再验证）",
                              "en": "  timestamps: NOT required (it stops verifying when the certificate expires)",
                              "ja": "  時刻認証：不要（証明書が切れると確かめられなくなります）"},
    "preview.copy": {"zh": "  复制到：{path}", "en": "  copied to: {path}", "ja": "  複製先：{path}"},
    "preview.trust": {"zh": "  信任：{what}", "en": "  trust: {what}", "ja": "  信頼：{what}"},
    "preview.files": {"zh": "  文件：", "en": "  files:", "ja": "  ファイル："},
    "preview.missing": {"zh": "    找不到 {path}", "en": "    MISSING  {path}", "ja": "    見つかりません {path}"},
    "preview.file": {"zh": "    {name}  {size} 字节  {state}",
                     "en": "    {name}  {size} bytes  {state}",
                     "ja": "    {name}  {size} バイト  {state}"},

    # the outcome, said by the window
    "outcome.summary": {"zh": "{signed} 个已签名，{skipped} 个跳过，{failed} 个失败，{copied} 个已复制",
                        "en": "{signed} signed, {skipped} skipped, {failed} failed, {copied} copied",
                        "ja": "署名 {signed} 件、見送り {skipped} 件、失敗 {failed} 件、複製 {copied} 件"},
    "outcome.signed": {"zh": "  已签名  {name}", "en": "  signed    {name}", "ja": "  署名    {name}"},
    "outcome.skipped": {"zh": "  跳过    {name}：{why}", "en": "  skipped   {name}: {why}",
                        "ja": "  見送り  {name}：{why}"},
    "outcome.failed": {"zh": "  失败    {name}：{why}", "en": "  failed    {name}: {why}",
                       "ja": "  失敗    {name}：{why}"},
    "outcome.copied": {"zh": "  复制    {source} → {target}", "en": "  copied    {source} -> {target}",
                       "ja": "  複製    {source} → {target}"},
    "outcome.trusted": {"zh": "  信任    {store}", "en": "  trusted   {store}", "ja": "  信頼    {store}"},
    "outcome.not_an_artifact": {"zh": "不是能签名的东西（{kind}）",
                                "en": "not something Authenticode signs ({kind})",
                                "ja": "署名できる種類ではありません（{kind}）"},
    "outcome.already_signed": {"zh": "已经带签名了", "en": "it already carries a signature",
                               "ja": "すでに署名があります"},

    # the audit, said by the window
    "verdict.unchanged": {"zh": "仍与记录一致", "en": "unchanged", "ja": "記録のまま"},
    "verdict.superseded": {"zh": "已被后来签的那一份取代", "en": "superseded", "ja": "あとで署名したものに代わった"},
    "verdict.changed": {"zh": "被账本没有记录的东西改过", "en": "changed", "ja": "記録に無い変更"},
    "verdict.signer differs": {"zh": "字节与记录一致，但签名者不是记录里的那个",
                               "en": "the bytes are on record, the signer is not",
                               "ja": "バイトは記録のまま、署名者だけが違う"},
    "verdict.now unsigned": {"zh": "签名没了", "en": "now unsigned", "ja": "署名が無くなった"},
    "verdict.gone": {"zh": "文件不在了", "en": "gone", "ja": "ファイルが無い"},
    "verdict.published": {"zh": "已发布", "en": "published", "ja": "公開済み"},
    "verdict.relocated": {"zh": "另有副本", "en": "relocated", "ja": "別の場所に複製"},
    "audit.replaced_by": {"zh": "    后来签的是 {when}", "en": "    replaced by {when}",
                          "ja": "    あとで署名したもの {when}"},
    "audit.summary": {"zh": "{records} 条记录：{unchanged} 条仍一致，{changed} 条被账本解释不了的改动，"
                            "{signer} 条字节一致但签名者对不上，"
                            "{unsigned} 条签名没了，{gone} 条文件不在",
                      "en": "{records} record(s): {unchanged} unchanged, {changed} changed by "
                            "something this ledger has no record of, {signer} whose bytes are on "
                            "record but whose signer is not, {unsigned} now unsigned, {gone} gone",
                      "ja": "記録 {records} 件：{unchanged} 件は記録のまま、{changed} 件は記録に無い変更、"
                            "{signer} 件はバイトが記録のままで署名者だけが違い、"
                            "{unsigned} 件は署名が無くなり、{gone} 件はファイルがありません"},
    "audit.broken": {"zh": "账本里有 {count} 行读不出来", "en": "{count} unreadable line(s) in the ledger",
                     "ja": "読めない行が {count} 行あります"},
}


def translate(key: str, language: str, **fields) -> str:
    """One string, in one language.

    A missing key or a missing translation returns the key itself rather than an empty line: a
    window with a gap in it is easier to fix than a window that has silently stopped saying
    something.
    """
    entry = STRINGS.get(key)
    if not entry:
        return key
    text = entry.get(language) or entry.get(DEFAULT_LANGUAGE) or key
    if fields:
        try:
            return text.format(**fields)
        except (KeyError, IndexError):
            return text
    return text


def normalise(language: str) -> str:
    wanted = (language or "").strip().lower()
    if wanted.startswith("zh"):
        return "zh"
    if wanted.startswith("ja"):
        return "ja"
    if wanted.startswith("en"):
        return "en"
    return ""


def from_environment() -> str:
    return normalise(os.environ.get("ONLYSIGN_LANG", ""))
