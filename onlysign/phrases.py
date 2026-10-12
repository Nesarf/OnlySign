"""What the gate says while it works, in every language it can say it in.

Separate from ``i18n``, which is the window's table: these are the lines a person sees in a console
when they run a package's gate, and the two never share a window. Separate from the notice too,
because the notice is the thing being *said* and this is the running commentary around it.

The generated PowerShell script cannot hold any of this. It has to stay ASCII -- Windows PowerShell
decodes a script with no byte order mark using the machine's ANSI code page, so a Chinese or
Japanese line written into it arrives as mojibake -- so the gate writes these to a UTF-8 sidecar as
``key = value`` lines and the script reads them back. The English in this file doubles as the
fallback inside the script, so a missing sidecar costs the translation and never the sentence.
"""

from __future__ import annotations

LANGUAGES = ("en", "zh", "ja")

PHRASES: dict[str, dict[str, str]] = {
    "package": {"en": "package : ", "zh": "包　　：", "ja": "包　　　："},
    "signer": {"en": "signer  : ", "zh": "签名者：", "ja": "署名者　："},
    "stamped": {"en": "stamped : ", "zh": "时间戳：", "ja": "時刻認証："},
    "verdict": {"en": "verdict : ", "zh": "系统判定：", "ja": "判定　　："},

    "signer_none": {"en": "nothing -- the file carries no signature",
                    "zh": "没有——这个文件不带签名",
                    "ja": "ありません（このファイルに署名が付いていません）"},
    "carried_note": {
        "en": "          read from the file itself, so a catalog entry cannot answer for it",
        "zh": "          这是从文件本身读出来的，系统目录里的记录代替不了它",
        "ja": "          ファイルそのものから読み取った値です。目録の記録では代われません"},
    "stamped_yes": {
        "en": "yes -- it stays verifiable after the certificate expires",
        "zh": "有——证书到期之后它仍然可以被验证",
        "ja": "あり（証明書が切れたあとも確かめられます）"},
    "stamped_no": {
        "en": "no -- it stops verifying when the certificate expires",
        "zh": "没有——证书一到期就无法再验证",
        "ja": "なし（証明書が切れると確かめられなくなります）"},

    "verdict_note_a": {
        "en": "          what Windows says about this file, catalogs included.",
        "zh": "          这是 Windows 对这个文件的说法，其中包含系统目录。它回答的可能不是上面那一行",
        "ja": "          これは Windows がこのファイルについて述べたことで、目録の記録も含みます。"},
    "verdict_note_b": {
        "en": "          It can answer about a different signature than the one above, which is why the"
              " check below uses that signature and not this verdict.",
        "zh": "          的那个签名——所以下面核查用的是上面那一行，而不是这一行。",
        "ja": "          上の行とは別の署名について答えていることがあります。下の確認は上の行を使います。"},
    "selfsigned_a": {
        "en": "          A self-signed certificate is its own root, so no valid signature is",
        "zh": "          自签证书自己就是根，在把它公开的一半装进这台机器之前，系统不会",
        "ja": "          自己署名の証明書はそれ自体が根なので、公開する半分をこの端末に入れるまで"},
    "selfsigned_b": {
        "en": "          reported until its public half is trusted on this machine. The check below",
        "zh": "          报告有效的签名。下面的核查并不依赖这一点。",
        "ja": "          有効な署名としては報告されません。下の確認はそれにも依りません。"},

    "incomplete": {
        "en": "This package is incomplete: the file it installs is not beside this script.",
        "zh": "这个包不完整：它要安装的文件不在此脚本旁边。",
        "ja": "この包は不完全です。入れるはずのファイルがこの脚本の隣にありません。"},
    "expected": {"en": "  expected: ", "zh": "  应该在这里：", "ja": "  あるはずの場所："},

    "no_signature_a": {
        "en": "This package carries no signature, so nothing here can vouch for who made it.",
        "zh": "这个包不带签名，因此无法证明它是谁做的。",
        "ja": "この包には署名がありません。誰が作ったのかを確かめる手立てがありません。"},
    "no_signature_b": {"en": "Installation was not started.",
                       "zh": "没有开始安装。", "ja": "取り付けは始めていません。"},

    "wrong_a": {"en": "This package is NOT signed by the identity it claims.",
                "zh": "这个包并不是它自称的那个身份签的。",
                "ja": "この包は、名乗っている相手の署名ではありません。"},
    "wrong_expected": {"en": "  expected: ", "zh": "  应该是：", "ja": "  本来："},
    "wrong_found": {"en": "  found   : ", "zh": "  实际是：", "ja": "  実際："},
    "wrong_b": {"en": "Installation was not started. If you did not expect this, do not run the file.",
                "zh": "没有开始安装。如果你没料到会这样，请不要运行这个文件。",
                "ja": "取り付けは始めていません。心当たりがなければ、このファイルを実行しないでください。"},

    "no_timestamp_a": {
        "en": "The signature carries no timestamp, so it cannot be vouched for once the certificate",
        "zh": "这个签名没有时间戳，证书到期之后就无从担保。",
        "ja": "この署名には時刻認証がないので、証明書が切れたあとは保証できません。"},
    "no_timestamp_b": {"en": "expires. Installation was not started.",
                       "zh": "没有开始安装。", "ja": "取り付けは始めていません。"},

    # The one line a person meets by choosing not to go on, and the only place here where the words
    # are allowed to have any weather in them. Everything else in this file is a refusal this tool
    # made -- a signature that does not match, a timestamp that is missing -- and a warning should
    # read plainly, because atmosphere over a warning hides the warning. Declining is the person's
    # own act, so it can sound like one.
    "not_started": {"en": "The installation cannot be carried out at this moment.",
                    "zh": "安装不能在这一刻进行。",
                    "ja": "インストールは今この時点では行えません。"},
    # The reply to yes. The game sets those two words in spaced capitals on a dark field; a console
    # has no font to choose, but it has tracking and it has a frame, and between them that is most of
    # what the line is. ASCII only, so it survives any code page -- a banner that arrives as question
    # marks is worse than no banner.
    "bonfire": {"en": "+-------------------------+\n"
                      "|  B O N F I R E   L I T  |\n"
                      "+-------------------------+",
                "zh": "+-------------------------+\n"
                      "|  B O N F I R E   L I T  |\n"
                      "+-------------------------+",
                "ja": "+-------------------------+\n"
                      "|  B O N F I R E   L I T  |\n"
                      "+-------------------------+"},
    "starting": {"en": "Starting the installer...", "zh": "正在启动安装程序…",
                 "ja": "取り付けを始めます…"},
    # The closing line for a run that did not finish. Same register as declining: the thing could not
    # be done, said plainly and once, rather than a stack of adjectives.
    "signing_failed": {"en": "The signing could not be carried out.",
                       "zh": "签名不能在这一刻完成。",
                       "ja": "署名は今この時点では行えません。"},
    "answered_cli": {"en": "   [answered on the command line]", "zh": "   [已在命令行上作答]",
                     "ja": "   [命令行で答えました]"},
    "answer_again": {"en": "Please answer Y or N.", "zh": "请回答 Y 或 N。",
                     "ja": "Y か N で答えてください。"},
}


def table(language: str) -> dict[str, str]:
    """One language's phrases, with English filling anything a translation missed."""
    return {key: entry.get(language) or entry.get("en", "") for key, entry in PHRASES.items()}


# A newline inside a value, written as the two characters a reader of the sidecar can see. The format
# is one key per line, which a value of several lines would break; escaping it keeps the file
# readable by a person and still lets a banner be a banner. The backslash is built rather than typed,
# so this file never carries an escape sequence of its own -- that mistake has cost enough today.
NEWLINE_ESCAPE = chr(92) + "n"


def sidecar(language: str) -> str:
    """The ``key = value`` text the gate writes and its script reads back."""
    lines = [f"{key} = {value}".replace("\n", NEWLINE_ESCAPE)
             for key, value in table(language).items() if value]
    return "\n".join(lines) + "\n"
