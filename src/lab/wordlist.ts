/**
 * 「よくあるパスワード」の辞書（演習用の短い一覧。実在の漏えいリストの転載ではなく、広く知られた弱いパスワードの例）。
 * password-storage の辞書攻撃と、bruteforce の攻撃ツールで使う。先頭 30 語が bruteforce の辞書。
 */
export const COMMON_PASSWORDS: readonly string[] = [
  // ---- 先頭 30 語（bruteforce の攻撃ツールが使う） ----
  "123456", "password", "12345678", "qwerty", "123456789", "12345", "1234", "111111", "1234567", "dragon",
  "123123", "baseball", "abc123", "football", "monkey", "letmein", "shadow", "master", "666666", "qwertyuiop",
  "123321", "mustang", "1234567890", "michael", "654321", "superman", "1qaz2wsx", "sunshine", "iloveyou", "welcome",
  // ---- 以降（password-storage の辞書攻撃で使う） ----
  "Password1", "password1", "Password123", "password123", "passw0rd", "p@ssw0rd", "qwerty123", "welcome1", "welcome123", "admin",
  "admin123", "administrator", "root", "toor", "guest", "login", "changeme", "secret", "test", "test1234",
  "1q2w3e4r", "1q2w3e", "qazwsx", "zxcvbnm", "zxcvbn", "asdfgh", "asdfghjkl", "asdf1234", "qwer1234", "1234qwer",
  "pass1234", "abc12345", "abcd1234", "aaaaaa", "aaaa1111", "7777777", "777777", "555555", "000000", "121212",
  "112233", "131313", "159753", "11111111", "987654321", "696969", "trustno1", "killer", "hunter", "buster",
  "soccer", "hockey", "ranger", "harley", "batman", "tigger", "charlie", "robert", "thomas", "daniel",
  "george", "joshua", "andrew", "jordan", "jessica", "jennifer", "michelle", "amanda", "ashley", "nicole",
  "chelsea", "matthew", "taylor", "maggie", "pepper", "ginger", "princess", "freedom", "summer", "cheese",
  "computer", "starwars", "matrix", "thunder", "yankees", "dallas", "austin", "access", "biteme", "love",
  "hello", "hello123", "iloveyou1", "monkey123", "dragon123", "football1", "baseball1", "superman1", "master1", "letmein1",
  "sakura", "tokyo", "nippon", "samurai", "naruto", "pokemon", "doraemon", "yamato", "ichiro", "tanaka",
  "suzuki", "yamada", "kitty", "angel", "lovely", "flower", "rainbow", "butterfly", "chocolate", "cookie",
] as const;

/** 先頭 30 語。bruteforce の攻撃ツール（クライアント JS）に渡す */
export const TOP_PASSWORDS = COMMON_PASSWORDS.slice(0, 30);
