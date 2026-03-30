그럼 짧게 보이는 값이랑 원본 전체 message 값을 둘 다 따로 넣어두면 돼.

즉:
	•	value에는 20자 자른 텍스트
	•	data-message에는 원본 전체 message
	•	클릭 밖에서
	•	data-name
	•	data-bname
	•	data-message
를 꺼내서 쓰면 됨

예시 이렇게.

{
    field: "message",
    title: "알림",
    template: function (dataItem) {
        var fullText = dataItem.message || "";
        var shortText = fullText.length > 20 ? fullText.substring(0, 20) + "..." : fullText;

        var safeShortText = shortText.replace(/"/g, "&quot;");
        var safeFullText = fullText.replace(/"/g, "&quot;");
        var safeName = (dataItem.name || "").replace(/"/g, "&quot;");
        var safeBname = (dataItem.bname || "").replace(/"/g, "&quot;");

        return '<input type="text" ' +
               'class="grid-text-click" ' +
               'value="' + safeShortText + '" ' +
               'data-message="' + safeFullText + '" ' +
               'data-name="' + safeName + '" ' +
               'data-bname="' + safeBname + '" ' +
               'readonly ' +
               'style="cursor:pointer;" />';
    }
}

그리고 밖에서:

$(document).on("click", ".grid-text-click", function () {
    var name = $(this).data("name");
    var bname = $(this).data("bname");
    var message = $(this).data("message");

    console.log("name:", name);
    console.log("bname:", bname);
    console.log("message:", message);

    funca(true, name, bname, message);
});

핵심은 이거야:
	•	화면에 보이는 건 value
	•	실제 넘길 원본은 data-message

그래서 보이는 건 잘려도, 클릭했을 때는 원본 전체 message를 그대로 쓸 수 있어.

조금 더 안전하게 하려면 작은 함수로 escape 처리해도 좋아:

function escapeAttr(value) {
    return (value || "")
        .replace(/&/g, "&amp;")
        .replace(/"/g, "&quot;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;");
}

그리고 template 안에서:

var safeFullText = escapeAttr(fullText);

이렇게 쓰면 더 안전해.

제일 짧게 말하면, 네 경우는 data-message에 원본 넣고 클릭 밖에서 꺼내 쓰는 방식이 맞아.

응, 밖으로 뺀 방식으로 다시 쓰면 이렇게야.

핵심은:
	•	*Kendo Grid template 안에는 class랑 data-만 넣고
	•	클릭 이벤트는 바깥에서 $(document).on(...)으로 연결

1) Kendo Grid 컬럼 template

예를 들어 message, name, bname 필드를 쓴다고 하면:

{
    field: "message",
    title: "알림",
    template: function (dataItem) {
        var text = dataItem.message || "";
        var shortText = text.length > 20 ? text.substring(0, 20) + "..." : text;

        var safeValue = shortText.replace(/"/g, "&quot;");
        var safeName = (dataItem.name || "").replace(/"/g, "&quot;");
        var safeBname = (dataItem.bname || "").replace(/"/g, "&quot;");

        return '<input type="text" ' +
               'class="grid-text-click" ' +
               'value="' + safeValue + '" ' +
               'data-name="' + safeName + '" ' +
               'data-bname="' + safeBname + '" ' +
               'readonly ' +
               'style="cursor:pointer;" />';
    }
}

2) 바깥에서 클릭 이벤트 연결

$(document).on("click", ".grid-text-click", function () {
    var name = $(this).data("name");
    var bname = $(this).data("bname");

    funca(true, name, bname);
});

3) 원하면 id나 다른 값도 같이 넘길 수 있음

template: function (dataItem) {
    var text = dataItem.message || "";
    var shortText = text.length > 20 ? text.substring(0, 20) + "..." : text;

    return '<input type="text" ' +
           'class="grid-text-click" ' +
           'value="' + shortText.replace(/"/g, "&quot;") + '" ' +
           'data-id="' + dataItem.id + '" ' +
           'data-name="' + (dataItem.name || "").replace(/"/g, "&quot;") + '" ' +
           'data-bname="' + (dataItem.bname || "").replace(/"/g, "&quot;") + '" ' +
           'readonly ' +
           'style="cursor:pointer;" />';
}

$(document).on("click", ".grid-text-click", function () {
    var id = $(this).data("id");
    var name = $(this).data("name");
    var bname = $(this).data("bname");

    console.log(id);
    funca(true, name, bname);
});

4) 커서만 CSS로 빼고 싶으면

.grid-text-click {
    cursor: pointer;
}

그럼 template에서는 style 빼도 돼:

return '<input type="text" class="grid-text-click" ... readonly />';

제일 짧은 형태

template: function (dataItem) {
    var text = dataItem.message || "";
    var shortText = text.length > 20 ? text.substring(0, 20) + "..." : text;

    return '<input type="text" class="grid-text-click" ' +
           'value="' + shortText.replace(/"/g, "&quot;") + '" ' +
           'data-name="' + (dataItem.name || "").replace(/"/g, "&quot;") + '" ' +
           'data-bname="' + (dataItem.bname || "").replace(/"/g, "&quot;") + '" ' +
           'readonly />';
}

$(document).on("click", ".grid-text-click", function () {
    funca(true, $(this).data("name"), $(this).data("bname"));
});

원하면 이걸 네 현재 Kendo Grid columns 코드 모양에 맞게 바로 끼워서 정리해줄게.

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