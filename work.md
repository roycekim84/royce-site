응, 이런 느낌으로 만들면 돼.
네가 적은 형태 보면 파라미터 받아서 DB 조회하고 List<alist> 로 리턴하는 메서드가 필요한 거잖아.

예시를 SqlConnection 기준으로 하나 써보면:

public List<AList> AFunc(string a, string b, string c)
{
    var result = new List<AList>();

    string connStr = "Server=서버명;Database=DB명;User Id=아이디;Password=비밀번호;";

    string sql = @"
        SELECT Col1, Col2, Col3
        FROM YourTable
        WHERE ColA = @A
          AND ColB = @B
          AND ColC = @C";

    using (SqlConnection conn = new SqlConnection(connStr))
    using (SqlCommand cmd = new SqlCommand(sql, conn))
    {
        cmd.Parameters.AddWithValue("@A", a);
        cmd.Parameters.AddWithValue("@B", b);
        cmd.Parameters.AddWithValue("@C", c);

        conn.Open();

        using (SqlDataReader reader = cmd.ExecuteReader())
        {
            while (reader.Read())
            {
                result.Add(new AList
                {
                    Col1 = reader["Col1"]?.ToString(),
                    Col2 = reader["Col2"]?.ToString(),
                    Col3 = reader["Col3"]?.ToString()
                });
            }
        }
    }

    return result;
}

모델은 예를 들어:

public class AList
{
    public string Col1 { get; set; }
    public string Col2 { get; set; }
    public string Col3 { get; set; }
}

만약 네가 말한 querysingle 스타일이면 Dapper 비슷한 느낌일 수도 있어서, 그럼 더 짧게도 가능해:

public List<AList> AFunc(string a, string b, string c)
{
    using (var conn = new SqlConnection("Server=서버명;Database=DB명;User Id=아이디;Password=비밀번호;"))
    {
        string sql = @"
            SELECT Col1, Col2, Col3
            FROM YourTable
            WHERE ColA = @A
              AND ColB = @B
              AND ColC = @C";

        return conn.Query<AList>(sql, new
        {
            A = a,
            B = b,
            C = c
        }).ToList();
    }
}

중요한 거 하나:
	•	QuerySingle 은 한 건만 받을 때
	•	List<T> 로 받을 거면 보통 Query<T> 를 써

즉 네 경우엔 List<AList> 리턴이면 QuerySingle 보다 Query 가 더 맞아.

한 건만 받을 거면 이렇게:

public AList AFunc(string a, string b, string c)
{
    using (var conn = new SqlConnection("Server=서버명;Database=DB명;User Id=아이디;Password=비밀번호;"))
    {
        string sql = @"
            SELECT Col1, Col2, Col3
            FROM YourTable
            WHERE ColA = @A
              AND ColB = @B
              AND ColC = @C";

        return conn.QuerySingleOrDefault<AList>(sql, new
        {
            A = a,
            B = b,
            C = c
        });
    }
}

네 스타일에 최대한 맞춰서 쓰면 대충 이런 모양이 제일 비슷함:

public List<AList> AFunc(string a, string b, string c)
{
    var ret = new List<AList>();

    using (var conn = new SqlConnection(connStr))
    {
        string sql = @"SELECT Col1, Col2, Col3
                       FROM YourTable
                       WHERE ColA = @A
                         AND ColB = @B
                         AND ColC = @C";

        ret = conn.Query<AList>(sql, new { A = a, B = b, C = c }).ToList();
    }

    return ret;
}

지금 네가 쓰는 게
	•	순수 SqlCommand
	•	Dapper
	•	EF Core
중에 뭐인지에 따라 모양이 조금씩 달라져.

네 코드 기준으로 dbconnection querysingle 이라고 한 거 보면 Dapper 스타일 같아서, 그 버전으로 다시 딱 맞춰 쓰면 아마 이거일 가능성이 큼:

public List<AList> AFunc(string a, string b, string c)
{
    using (var db = new SqlConnection(connStr))
    {
        string sql = @"
            SELECT *
            FROM YourTable
            WHERE A = @A
              AND B = @B
              AND C = @C";

        return db.Query<AList>(sql, new { A = a, B = b, C = c }).ToList();
    }
}

원하면 내가 다음 답변에서 네가 바로 붙여넣을 수 있게
프로시저 호출 버전
일반 SELECT 버전
둘 다 만들어줄게.


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