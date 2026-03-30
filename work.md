그건 보통 프로시저의 SELECT 1 결과값을 받은 게 아니라,
C#에서 실행 결과(return value 또는 affected rows) 를 다른 방식으로 받고 있어서 그래.

가장 흔한 이유는 이거야:

1) ExecuteNonQuery()를 쓰고 있음

이 경우 ret에는 SELECT 결과값이 안 들어가고,
보통 영향받은 행 수가 들어가.
그리고 SELECT만 한 경우엔 -1 이 나오는 일이 흔해.

예를 들어 C#이 이거면:

var ret = cmd.ExecuteNonQuery();

프로시저 안의

SELECT 1

을 받는 게 아니라,
“몇 행 영향 있었냐” 비슷한 값을 받는 거라서 -1 나올 수 있어.

⸻

2) SELECT 1 을 받고 싶으면 ExecuteScalar() 써야 함

이렇게 해야 해:

var ret = Convert.ToInt32(cmd.ExecuteScalar());

이러면 프로시저 안에서

SELECT 1

한 첫 번째 값을 받아와.

예시

프로시저:

CREATE PROCEDURE dbo.TestProc
AS
BEGIN
    SELECT 1;
END

C#:

using (var cmd = new SqlCommand("dbo.TestProc", conn))
{
    cmd.CommandType = CommandType.StoredProcedure;
    var ret = Convert.ToInt32(cmd.ExecuteScalar());
}

이러면 ret = 1

⸻

3) 프로시저의 RETURN 값을 받고 싶은 걸 수도 있음

SELECT 1이 아니라 진짜 return code를 받고 싶으면
SQL은 이렇게:

CREATE PROCEDURE dbo.TestProc
AS
BEGIN
    RETURN 1;
END

C#은 이렇게:

using (var cmd = new SqlCommand("dbo.TestProc", conn))
{
    cmd.CommandType = CommandType.StoredProcedure;

    var returnParam = new SqlParameter();
    returnParam.Direction = ParameterDirection.ReturnValue;
    cmd.Parameters.Add(returnParam);

    cmd.ExecuteNonQuery();

    var ret = Convert.ToInt32(returnParam.Value);
}

이 경우에야 ret = 1

⸻

정리

네 상황은 거의 확률 높게 이거야:
	•	프로시저 안: SELECT 1
	•	C# 쪽: ExecuteNonQuery()

그래서:
	•	기대: 1
	•	실제: -1

해결
	•	SELECT 1 결과를 받고 싶다 → ExecuteScalar()
	•	프로시저 반환코드가 필요하다 → RETURN 1 + ReturnValue 파라미터

한 줄로 말하면:
지금 ret은 SELECT 1 값을 받은 게 아니라 ExecuteNonQuery()의 실행 결과를 받은 거라서 -1이 나온 거야.

C# 코드 한 줄 보여주면 정확히 어느 방식으로 바꿔야 하는지 바로 짚어줄게.