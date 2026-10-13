"""Localized account reminder messages; translation content only."""

TEMPLATES: dict[str, dict[str, str]] = {
    "en": {
        "expired": "Canvas API token expired",
        "soon": "Canvas API token expires soon",
        "body": "Your stored Canvas API token has an expiry date of {date}.\nCreate a new token in Canvas, then update it at {url}/account/token.\nNever reply with or email your token.",
    },
    "zh": {
        "expired": "Canvas API 令牌已到期",
        "soon": "Canvas API 令牌即将到期",
        "body": "您绑定的 Canvas API 令牌到期时间为 {date}。\n请在 Canvas 创建新令牌，然后访问 {url}/account/token 更新。\n请勿通过邮件回复或发送令牌。",
    },
}
