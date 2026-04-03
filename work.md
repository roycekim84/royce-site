가능해.
그 abc 값은 지금 코드상 tempid:temppw 문자열을 Base64로 인코딩한 값이라서, 역으로 Base64 디코딩하면 원문이 나와.

즉 원리는 이거야:

tempid:temppw

를 ASCII 바이트로 바꾼 뒤 Base64로 만든 거라서,
디코딩하면 다시 저 형태의 문자열이 나옴.

역변환 코드

string abc = "여기에 base64값";

string decoded = Encoding.ASCII.GetString(Convert.FromBase64String(abc));

// 보통 "id:pw" 형태
string[] parts = decoded.Split(':');

string tempid = parts[0];
string temppw = parts[1];


⸻

예시

string abc = "YWJjOjEyMzQ=";

string decoded = Encoding.ASCII.GetString(Convert.FromBase64String(abc));
// decoded = "abc:1234"

string[] parts = decoded.Split(':');

string tempid = parts[0];   // "abc"
string temppw = parts[1];   // "1234"


⸻

주의할 점

Split(':')는 보통 되는데,
비밀번호 안에 : 문자가 들어있을 가능성이 있으면 그냥 Split(':') 하면 잘못 나눠질 수 있어.

그럴 땐 첫 : 기준으로만 자르는 게 더 안전해:

string abc = "여기에 base64값";

string decoded = Encoding.ASCII.GetString(Convert.FromBase64String(abc));

int idx = decoded.IndexOf(':');

string tempid = decoded.Substring(0, idx);
string temppw = decoded.Substring(idx + 1);


⸻

핵심

Base64는 암호화가 아니라 인코딩이라서, 값만 알면 원래 문자열을 다시 볼 수 있어.

abc 값을 주면 내가 바로 원문이 어떤 형식인지도 같이 풀어서 설명해줄 수 있어.