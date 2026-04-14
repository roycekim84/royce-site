응, 가능은 해.

Web.config 에 꼭 적어야만 DB 접속되는 건 아니고, 코드에서 직접 연결 문자열 써서 접속할 수도 있어.

예를 들면:

using System.Data.SqlClient;

string connStr = "Server=서버명;Database=DB명;User Id=아이디;Password=비번;";

using (SqlConnection conn = new SqlConnection(connStr))
{
    conn.Open();

    string sql = "SELECT * FROM 테이블명";
    using (SqlCommand cmd = new SqlCommand(sql, conn))
    using (SqlDataReader reader = cmd.ExecuteReader())
    {
        while (reader.Read())
        {
            var value = reader["컬럼명"].ToString();
        }
    }
}

즉,
	•	Web.config 없이도
	•	코드 안에서 connection string 만들고
	•	바로 특정 테이블 조회 가능

근데 실무에선 보통 Web.config 나 appsettings.json 에 빼는 이유가 있어:
	•	DB 주소 바뀌면 코드 수정 없이 설정만 바꾸려고
	•	아이디/비번을 코드에 박아두면 위험해서
	•	운영/개발 환경별로 다르게 쓰려고

그리고 또 가능 한 방법은:
	•	환경변수에서 읽기
	•	별도 설정 파일에서 읽기
	•	암호화된 저장소에서 읽기

즉 핵심은
DB 접속 자체는 가능하지만, Web.config 는 “관리 편하게 하려고” 쓰는 거지 필수는 아니다 라고 보면 돼.

단, 네가 지금 말하는 게
“기존 프로젝트에서 Web.config 에 connectionString 안 보이는데도 DB 조회가 된다”
이거면 다른 데서 가져오는 걸 수도 있어:
	•	코드에 하드코딩
	•	app.config
	•	환경변수
	•	공통 라이브러리 dll 내부
	•	DI 등록 코드
	•	암호화된 설정값 복호화
	•	다른 설정 파일(json, xml 등)

이 경우엔 프로젝트 전체에서 이런 걸 검색해봐:

connectionString
SqlConnection
Server=
Database=
Initial Catalog=
Data Source=

그리고 EF 쓰면:

UseSqlServer
DbContext
OnConfiguring

원하면 내가 “이 프로젝트가 DB 접속 문자열을 어디서 읽는지 찾는 법” 순서대로 딱 짚어줄게.