가능해. dataBound에서 값 기준으로 버튼 두 개 클래스 분기하면 돼.

네 조건은 이거지:
	•	null → 버튼 둘 다 btn-gray
	•	0 → btn1만 btn-blue, 나머지는 btn-gray
	•	1 → btn2만 btn-blue, 나머지는 btn-gray

그럼 핵심은 먼저 두 버튼 다 초기화하고, 값에 따라 하나만 파란색으로 바꾸는 거야.

예시:

dataBound: function () {
    var grid = this;

    grid.tbody.find("tr").each(function () {
        var data = grid.dataItem(this);
        var $tr = $(this);

        var $btn1 = $tr.find(".k-grid-btn1");
        var $btn2 = $tr.find(".k-grid-btn2");

        // 1) 먼저 둘 다 초기화
        $btn1.removeClass("btn-blue btn-gray");
        $btn2.removeClass("btn-blue btn-gray");

        // 2) 기본은 둘 다 gray
        $btn1.addClass("btn-gray");
        $btn2.addClass("btn-gray");

        // 3) 값에 따라 하나만 blue
        if (data.alert === 0) {
            $btn1.removeClass("btn-gray").addClass("btn-blue");
        } else if (data.alert === 1) {
            $btn2.removeClass("btn-gray").addClass("btn-blue");
        }
        // null이면 위 기본 상태 그대로 둘 다 gray
    });
}

만약 null 체크를 더 명확히 하고 싶으면

if (data.alert == null) {
    // 둘 다 gray 유지
} else if (data.alert === 0) {
    $btn1.removeClass("btn-gray").addClass("btn-blue");
} else if (data.alert === 1) {
    $btn2.removeClass("btn-gray").addClass("btn-blue");
}

값이 문자열 "0", "1"로 올 수도 있으면

가끔 서버에서 문자열로 오는 경우가 있어서, 그럴 땐 느슨하게 비교하거나 숫자로 변환해.

if (data.alert == null) {
    // 둘 다 gray
} else if (data.alert == 0) {
    $btn1.removeClass("btn-gray").addClass("btn-blue");
} else if (data.alert == 1) {
    $btn2.removeClass("btn-gray").addClass("btn-blue");
}

CSS 예시

.btn-gray {
    background-color: #d9d9d9 !important;
    color: #666 !important;
    border-color: #d9d9d9 !important;
}

.btn-blue {
    background-color: #2f80ed !important;
    color: #fff !important;
    border-color: #2f80ed !important;
}

네 command 클래스가 이런 식이면

command: [
    {
        name: "btn1",
        text: "버튼1",
        className: "my-btn k-grid-btn1"
    },
    {
        name: "btn2",
        text: "버튼2",
        className: "my-btn k-grid-btn2"
    }
]

위 dataBound 코드 그대로 붙이면 돼.

한 줄로 줄이면 이 패턴이야:

$btn1.add($btn2).removeClass("btn-blue btn-gray").addClass("btn-gray");
if (data.alert == 0) $btn1.removeClass("btn-gray").addClass("btn-blue");
if (data.alert == 1) $btn2.removeClass("btn-gray").addClass("btn-blue");

원하면 내가 이걸 네 현재 columns.command 코드 모양에 그대로 끼워 넣은 완성본으로 정리해줄게.

가능해. 다만 command.className 자체는 정적인 문자열이라서, 행마다 true/false에 따라 자동으로 달라지게 넣기엔 안 맞아. Kendo Grid 문서상 columns.command.className은 “커맨드 버튼에 적용되는 CSS 클래스”이고, command는 배열로 둘 수 있어. 또 command.visible은 행의 data item을 받아 버튼 표시 여부를 정할 수 있어.  ￼

그래서 네 요구사항처럼
각 행의 dataItem 값(true/false)에 따라 버튼 색 클래스를 다르게 하려면 보통 두 방법이 있어.

제일 무난한 방법

command는 그대로 쓰고, 그리드가 렌더링된 뒤 dataBound에서 각 행의 버튼 클래스를 바꿔주는 방식.

이게 좋은 이유:
	•	command의 클릭 핸들러 구조를 유지할 수 있음
	•	버튼 2개도 그대로 유지 가능
	•	true/false에 따라 클래스만 교체하면 됨

예시:

$("#grid").kendoGrid({
    dataSource: dataSource,
    dataBound: function () {
        var grid = this;

        grid.tbody.find("tr").each(function () {
            var dataItem = grid.dataItem(this);
            var $tr = $(this);

            var $btn1 = $tr.find(".k-grid-btn1");
            var $btn2 = $tr.find(".k-grid-btn2");

            $btn1.removeClass("btn-on btn-off")
                 .addClass(dataItem.btn1Yn ? "btn-on" : "btn-off");

            $btn2.removeClass("btn-on btn-off")
                 .addClass(dataItem.btn2Yn ? "btn-on" : "btn-off");
        });
    },
    columns: [
        { field: "name", title: "이름" },
        {
            title: "동작",
            width: 220,
            command: [
                {
                    name: "btn1",
                    text: "버튼1",
                    className: "cmd-btn k-grid-btn1",
                    click: function (e) {
                        e.preventDefault();
                        var tr = $(e.target).closest("tr");
                        var data = this.dataItem(tr);
                        console.log("btn1", data);
                    }
                },
                {
                    name: "btn2",
                    text: "버튼2",
                    className: "cmd-btn k-grid-btn2",
                    click: function (e) {
                        e.preventDefault();
                        var tr = $(e.target).closest("tr");
                        var data = this.dataItem(tr);
                        console.log("btn2", data);
                    }
                }
            ]
        }
    ]
});

CSS:

.btn-on {
    background: #4caf50 !important;
    color: #fff !important;
    border-color: #4caf50 !important;
}

.btn-off {
    background: #d9d9d9 !important;
    color: #666 !important;
    border-color: #d9d9d9 !important;
}

여기서 포인트는:
	•	name: "btn1" 이면 버튼 anchor에 k-grid-btn1 클래스가 붙음
	•	그래서 dataBound에서 .k-grid-btn1, .k-grid-btn2를 찾아 행별로 클래스 교체 가능
	•	click 안에서는 공식 예제처럼 this.dataItem(tr)로 현재 행 데이터를 읽으면 됨. Kendo 문서도 커스텀 command의 click 함수에서 this가 grid 인스턴스이고, closest("tr") 후 dataItem(tr) 패턴을 보여준다.  ￼

버튼을 아예 숨기고 싶을 때

색만 바꾸는 게 아니라 어떤 행에서는 버튼을 안 보이게 하고 싶으면 command.visible도 쓸 수 있어. visible은 row 초기화 때 data item을 받아 표시 여부를 결정한다.  ￼

예:

{
    name: "btn2",
    text: "버튼2",
    className: "cmd-btn k-grid-btn2",
    visible: function(dataItem) {
        return dataItem.btn2Yn === true;
    },
    click: function(e) { ... }
}

더 세밀하게 꾸미고 싶으면

columns.command.template도 있어. 이건 command 컬럼 내부 HTML을 더 자유롭게 바꿀 때 쓰고, 템플릿 안에서 click 핸들러가 동작하려면 k-grid-[command.name] 클래스를 넣어야 한다고 문서에 나와 있어.  ￼

예를 들면:

{
    command: [
        {
            name: "btn1",
            template: "<a class='k-button k-grid-btn1'>버튼1</a>",
            click: function(e) { ... }
        }
    ]
}

그런데 네 현재 상황은 이미 command 배열로 바꿨고, 클릭도 써야 하니까 지금은 dataBound에서 클래스만 갈아끼우는 방식이 제일 깔끔해.

한 줄로 정리하면:
command.className은 행별 동적 값으로 바꾸기 어렵고, dataBound에서 각 row의 dataItem을 보고 .k-grid-btn1, .k-grid-btn2에 btn-on / btn-off 클래스를 붙이는 방식이 가장 무난해.  ￼

네가 지금 쓰는 columns.command 코드 붙여주면 그 형태 그대로 true/false 클래스 적용 버전으로 바로 바꿔줄게.

응, 가능해.
Kendo Grid는 columns.template 로 컬럼 안 HTML을 커스텀할 수 있어서, 버튼 2개를 한 셀 안에 넣고, 각 버튼의 0/1 값에 따라 색만 다르게 줄 수 있어. 공식 문서도 columns.template가 셀 내용을 원하는 HTML로 렌더링할 때 쓰는 옵션이라고 안내해.  ￼

가장 무난한 패턴은 이거야.

1) 컬럼 템플릿에서 버튼 2개 만들기

예를 들어 데이터가 이런 느낌이라고 치면:
	•	btn1Yn: 0 또는 1
	•	btn2Yn: 0 또는 1

$("#grid").kendoGrid({
    dataSource: dataSource,
    columns: [
        { field: "name", title: "이름" },
        {
            title: "동작",
            width: 180,
            template: function(dataItem) {
                var btn1Class = dataItem.btn1Yn == 1 ? "btn-on" : "btn-off";
                var btn2Class = dataItem.btn2Yn == 1 ? "btn-on" : "btn-off";

                return ''
                    + '<button type="button" class="k-button action-btn ' + btn1Class + '" data-type="btn1" data-id="' + dataItem.id + '">버튼1</button>'
                    + ' '
                    + '<button type="button" class="k-button action-btn ' + btn2Class + '" data-type="btn2" data-id="' + dataItem.id + '">버튼2</button>';
            }
        }
    ]
});

이건 Kendo Grid의 columns.template를 함수로 써서 각 행의 dataItem 값을 읽고, 그 값에 따라 다른 HTML을 반환하는 방식이야. 공식 API 예제도 template를 문자열이나 함수로 써서 셀 내용을 커스터마이즈하는 방식을 보여줘.  ￼

⸻

2) 색만 다르게 보이게 CSS 주기

.btn-on {
    background-color: #4caf50;
    color: #fff;
    border-color: #4caf50;
}

.btn-off {
    background-color: #d9d9d9;
    color: #666;
    border-color: #d9d9d9;
}

그러면:
	•	값이 1이면 초록
	•	값이 0이면 회색

이런 식으로 바로 표현 가능해.

⸻

3) 클릭 이벤트는 이벤트 위임으로 처리

그리드는 다시 렌더링될 수 있어서 버튼에 직접 .click() 거는 것보다 이벤트 위임이 안전해.

$(document).on("click", "#grid .action-btn", function () {
    var id = $(this).data("id");
    var type = $(this).data("type");

    console.log("클릭됨", id, type);
});


⸻

만약 필드가 하나만 있고 그걸로 버튼 둘 다 상태를 나누는 거면

예를 들어 한 행에 들어오는 값이 하나이고:
	•	status1
	•	status2

가 아니라 진짜 한 값만 있으면, 그 값 기준으로 두 버튼 클래스를 따로 계산하면 돼.

예:

template: function(dataItem) {
    return ''
        + '<button type="button" class="k-button ' + (dataItem.useYn == 1 ? "btn-on" : "btn-off") + '">권한신청</button>'
        + ' '
        + '<button type="button" class="k-button ' + (dataItem.useYn == 0 ? "btn-on" : "btn-off") + '">해제</button>';
}


⸻

실무적으로 더 깔끔한 버전

삼항연산자가 길어지면 함수로 빼는 게 보기 편해.

function getStateClass(value) {
    return value == 1 ? "btn-on" : "btn-off";
}

$("#grid").kendoGrid({
    dataSource: dataSource,
    columns: [
        {
            title: "동작",
            template: function(dataItem) {
                return ''
                    + '<button type="button" class="k-button ' + getStateClass(dataItem.btn1Yn) + '">버튼1</button>'
                    + ' '
                    + '<button type="button" class="k-button ' + getStateClass(dataItem.btn2Yn) + '">버튼2</button>';
            }
        }
    ]
});


⸻

주의할 점

Kendo Grid 템플릿은 HTML을 그대로 넣을 수 있어서 편하지만, 버튼 라벨이나 데이터가 사용자 입력값이면 인코딩도 신경 써야 해. 공식 문서 예제도 템플릿에서 kendo.htmlEncode()를 쓰는 예를 보여줘.  ￼

⸻

네가 바로 가져다 쓰기 좋은 예시

$("#grid").kendoGrid({
    dataSource: dataSource,
    pageable: true,
    columns: [
        { field: "userNm", title: "사용자명" },
        {
            title: "권한",
            width: 220,
            template: function(dataItem) {
                var applyClass = dataItem.applyYn == 1 ? "btn-on" : "btn-off";
                var cancelClass = dataItem.cancelYn == 1 ? "btn-on" : "btn-off";

                return ''
                    + '<button type="button" class="k-button auth-btn ' + applyClass + '" data-mode="apply" data-id="' + dataItem.userId + '">신청</button>'
                    + ' '
                    + '<button type="button" class="k-button auth-btn ' + cancelClass + '" data-mode="cancel" data-id="' + dataItem.userId + '">해제</button>';
            }
        }
    ]
});

$(document).on("click", "#grid .auth-btn", function () {
    var userId = $(this).data("id");
    var mode = $(this).data("mode");

    console.log("userId:", userId, "mode:", mode);
});

.btn-on {
    background: #4caf50;
    color: #fff;
    border: 1px solid #4caf50;
}

.btn-off {
    background: #dcdcdc;
    color: #666;
    border: 1px solid #dcdcdc;
}

원하면 네가 실제로 쓰는 columns 코드 한 덩어리에 맞춰서 바로 끼워 넣는 형태로 바꿔줄게.



그건 보통 라우팅/가상경로/리라이트 규칙 차이 때문이야.

네 상황을 풀면 지금 이런 거지:
	•	주소/a → 상위
	•	주소/a/a1 → 정상 접근
	•	주소/a/a2 → 정상 접근

근데
	•	주소/a1 → 안 됨
	•	주소/a2 → 됨

즉 a2만 상위 /a 없이도 별도 경로로 매핑돼 있다는 뜻이야.

가능성 큰 순서대로 보면:

1) a2가 별도 라우트로 등록돼 있음

예를 들면 라우팅에 이런 게 있을 수 있어:

routes.MapRoute(
    name: "A2",
    url: "a2",
    defaults: new { controller = "A2", action = "Index" }
);

이러면 /a2 로 직접 들어가짐.

반면 a1은 이런 라우트가 없고 /a/a1만 잡혀 있으면 /a1은 안 돼.

⸻

2) 서버 쪽 리라이트/가상디렉터리 설정이 따로 있음

IIS나 웹서버에서
	•	/a2 → /a/a2
이렇게 리라이트해주는 규칙이 있을 수 있어.

예:
	•	web.config rewrite rules
	•	IIS virtual application
	•	reverse proxy 설정

그러면 코드상으론 /a/a2인데 외부에선 /a2도 열림.

⸻

3) 프론트에서 링크/베이스 경로가 다르게 잡힘

특히 화면이 cshtml / js 섞여 있으면
	•	href="/a2"
	•	href="/a/a2"

이런 식으로 하드코딩된 경우가 있어.

그래서 실제로는 같은 화면인데 접근 주소가 두 개 생길 수 있음.

⸻

4) a2가 Area/Controller 이름과 우연히 기본 라우트에 걸림

ASP.NET MVC 기본 라우트가 이런 식이잖아:

{controller}/{action}/{id}

그러면 /a2가
	•	controller = a2
	•	action = index
처럼 해석될 수 있어.

반면 a1은 그런 컨트롤러/액션 구조가 안 맞아서 실패할 수 있음.

즉 /a2가 의도치 않게 기본 라우트에 걸려서 열리는 경우도 꽤 흔해.

⸻

네가 바로 확인할 곳

1. RouteConfig.cs

가장 먼저 봐:
	•	App_Start/RouteConfig.cs
	•	AreaRegistration
	•	attribute routing 사용 여부

찾아볼 문자열:
	•	"a2"
	•	"a1"
	•	"a/{something}"
	•	MapRoute

⸻

2. 컨트롤러 이름

예를 들어
	•	A2Controller
가 있으면 /a2가 기본 라우트에 걸릴 수 있어.

특히 액션이 Index()면 더 가능성 큼.

⸻

3. web.config

이거 찾아봐:
	•	<rewrite>
	•	<rule>
	•	a2

만약 /a2를 /a/a2로 보내는 규칙 있으면 원인 확정.

⸻

4. 메뉴/링크 코드

cshtml/js에서
	•	/a2
	•	/a/a2

둘 다 쓰는지 검색해봐.

Visual Studio 전체 검색으로:

"/a2"
"/a/a2"
"a2"


⸻

왜 너는 a2가 안 되게 하고 싶은데 되냐

이건 거의 두 가지 중 하나야:
	1.	라우트가 중복 등록됨
	2.	기본 라우트가 우연히 /a2를 받아줌

특히 ASP.NET MVC에서는
A2Controller 가 있고 Index() 있으면
/a2가 그냥 열려버리는 경우가 흔해.

⸻

가장 가능성 큰 예시

예를 들어 네가 원한 건:
	•	/a/a2 만 허용

근데 실제 구조가:

public class A2Controller : Controller
{
    public ActionResult Index()
    {
        return View();
    }
}

기본 라우트가 살아 있으면
/a2도 같이 열릴 수 있어.

왜냐면 MVC가 이걸 그냥
	•	controller = A2
	•	action = Index
로 해석해버리니까.

반면 a1은 구조가 다르거나 별도 라우트 안 타서 /a1이 안 되는 거고.

⸻

막으려면

원인에 따라 다르지만 보통은:
	•	/a2로 잡히는 라우트 제거
	•	더 구체적인 /a/a2 라우트만 남기기
	•	기본 라우트보다 앞에 명시 라우트 추가
	•	컨트롤러 구조/Area 구조 재정리
	•	rewrite rule 제거

이쪽으로 가야 해.

⸻

제일 빠른 진단법

이 3개만 보면 거의 답 나와:
	•	RouteConfig.cs
	•	A2Controller 존재 여부
	•	web.config rewrite

⸻

한 줄로 말하면:
/a2가 되는 건 a2가 별도 라우트나 기본 라우트에 잡혀 있기 때문이고, /a1이 안 되는 건 그 매핑이 없어서야.

RouteConfig.cs랑 A2Controller 구조 보여주면 어디서 /a2가 살아나는지 바로 짚어줄 수 있어.