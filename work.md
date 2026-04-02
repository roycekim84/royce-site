응. 이 정규식은 “+국가코드-지역번호-번호-번호 형태만 허용” 하는 패턴이야. 그래서 지역번호가 없는 나라나 지역번호 길이가 1자리인 나라, 번호 구간 길이가 다른 나라에서 깨질 가능성이 커. 국제 전화번호는 ITU E.164 기준으로 최대 15자리이고 가변 길이라서, 국가별 번호 체계를 정규식 하나로 완벽하게 검증하기는 어렵다. libphonenumber 쪽도 전화번호에 대해 고정된 가정을 하면 쉽게 깨진다고 경고한다.  ￼

네 코드가 C#이라면 실제 문자열은 보통 이렇게 써야 해.

static string mobileReg = "^([+]\\d{1,3}-\\d{2,3})-\\d{2,6}-\\d{2,6}$";

또는 verbatim 문자열로 더 읽기 쉽게:

static string mobileReg = @"^([+]\d{1,3}-\d{2,3})-\d{2,6}-\d{2,6}$";

네가 적은 ₩₩d는 아마 에디터/폰트에서 \\d가 이상하게 보인 거고, 실제로는 \d를 뜻하는 거야.

이 정규식을 해석하면 이래.

^([+]\d{1,3}-\d{2,3})-\d{2,6}-\d{2,6}$

	•	^ : 문자열 시작
	•	[+] : + 문자 1개
	•	\d{1,3} : 숫자 1~3자리, 보통 국가코드
	•	- : 하이픈 1개
	•	\d{2,3} : 숫자 2~3자리, 네 코드에선 지역번호로 가정
	•	- : 하이픈 1개
	•	\d{2,6} : 숫자 2~6자리
	•	- : 하이픈 1개
	•	\d{2,6} : 숫자 2~6자리
	•	$ : 문자열 끝

즉 허용 예시는 이런 느낌이야.
	•	+82-10-1234-5678
	•	+1-212-555-1234

반대로 이런 건 막혀.
	•	+65-1234-5678 → 지역번호 구간이 없어서 실패
	•	+81-3-1234-5678 → 지역번호가 1자리라 실패
	•	+44-20-7123-4567-89 → 구간이 더 많아서 실패

그래서 이 정규식의 핵심 문제는 세 가지야.

첫째, 지역번호가 반드시 있어야 한다고 가정하고 있어. 그런데 싱가포르·홍콩 같은 곳은 국내 지역번호 개념이 없어서 이 가정이 깨질 수 있어. 둘째, 지역번호를 2~3자리로 고정했는데, 실제로는 1자리인 경우도 있고 더 복잡한 경우도 있다. 셋째, 전체 번호 체계가 가변 길이인데 하이픈 위치와 구간 개수를 너무 강하게 고정했다. ITU E.164는 국제번호를 가변 길이로 정의하고 최대 15자리라고만 규정한다.  ￼

그래서 네 요구처럼 지역번호 없는 나라도 통과시키려면, 최소한 지역번호 구간을 선택사항으로 바꿔야 해.

추천 1안은 네 현재 포맷을 최대한 유지하면서 완화한 버전이야.

static string mobileReg = @"^\+\d{1,3}(?:-\d{1,4})?-\d{2,6}-\d{2,6}$";

이걸 해석하면:
	•	^\+\d{1,3} : +와 국가코드 1~3자리
	•	(?:-\d{1,4})? : -지역번호 구간은 있어도 되고 없어도 됨
	•	-\d{2,6} : 다음 번호 구간
	•	-\d{2,6}$ : 마지막 번호 구간

이 패턴으로는 둘 다 돼.
	•	+82-10-1234-5678
	•	+65-1234-5678

그리고 1자리 지역번호도 허용되니까 이것도 돼.
	•	+81-3-1234-5678

이 버전은 네 기존 UI 포맷을 거의 안 바꾸면서 가장 덜 위험하게 고친 거야.

다만 이것도 한계는 있어. 예를 들어 어떤 나라는 번호를 2-2-2-2처럼 더 잘게 끊거나, 지역번호/가입자번호 길이가 훨씬 다양할 수 있다. 그래서 국제전화 “검증”을 엄밀하게 하려면 정규식만으로는 부족하고, 보통은 libphonenumber 같은 메타데이터 기반 라이브러리를 쓰는 쪽이 낫다. libphonenumber는 이런 “전화번호에 대한 잘못된 가정”을 정리해두고 있고, 국가별 파싱/검증을 위한 표준적인 선택지로 많이 쓰인다.  ￼

그래도 “지금 당장 regex만 바꿔야 한다”면, 목적별로 이렇게 추천해.

현재 입력 포맷을 유지하면서 지역번호 없는 나라까지 허용

static string mobileReg = @"^\+\d{1,3}(?:-\d{1,4})?-\d{2,6}-\d{2,6}$";

하이픈 구간 개수를 더 유연하게 허용

static string mobileReg = @"^\+\d{1,3}(?:-\d{1,6}){2,3}$";

이 두 번째는 뜻이:
	•	+국가코드
	•	뒤에 -숫자구간이 2번 또는 3번 온다

즉 이런 걸 다 허용해.
	•	+65-1234-5678
	•	+82-10-1234-5678
	•	+81-3-1234-5678

이게 국제번호 UI 입력용으론 더 현실적이야.

정리하면:

현재 정규식:

@"^([+]\d{1,3}-\d{2,3})-\d{2,6}-\d{2,6}$"

추천 정규식:

@"^\+\d{1,3}(?:-\d{1,4})?-\d{2,6}-\d{2,6}$"

더 유연한 추천:

@"^\+\d{1,3}(?:-\d{1,6}){2,3}$"

내 추천은 두 번째보다 세 번째가 실무적으로 더 낫고, 진짜 제대로 하려면 저장/전송은 E.164 비슷하게 숫자 중심으로 하고, 표시만 국가별 포맷팅하는 방식이야. E.164는 최대 15자리 가변 길이여서, 포맷 고정 검증은 본질적으로 취약하다.  ￼

원하면 내가 다음 답변에서 이 regex를 기준으로 허용 예시 / 실패 예시 표까지 만들어줄게.

맞아. 딱 거기 수정하면 돼.

지금 구조가:

_createPagerButton: function(text, css, handler) {
    var $link = $("<a>").attr("href", EMPTY_HREF).html(text).on("click", $.proxy(handler, this));

    return $("<span>").addClass(css).append($link);
},

이거면 현재는 a에만 click이 걸려 있어서, span 눌러도 반응 안 하는 상태야.

이렇게 바꾸면 됨

_createPagerButton: function(text, css, handler) {
    var self = this;

    var $link = $("<a>")
        .attr("href", EMPTY_HREF)
        .html(text)
        .on("click", $.proxy(handler, self));

    var $span = $("<span>")
        .addClass(css)
        .append($link)
        .on("click", function(e) {
            if($(e.target).is("a")) {
                return;
            }

            e.preventDefault();
            handler.call(self, e);
        });

    return $span;
},

왜 이렇게 바꾸냐

원래는:
	•	<a> 클릭 → handler 실행

이제는:
	•	<a> 클릭 → 기존처럼 handler
	•	<span> 클릭 → 직접 handler.call(self, e) 실행

즉 span을 눌러도 a 누른 것과 같은 효과가 나.

⸻

더 단순하게 하려면

내부 a를 강제로 클릭시키는 방식도 가능해:

_createPagerButton: function(text, css, handler) {
    var $link = $("<a>")
        .attr("href", EMPTY_HREF)
        .html(text)
        .on("click", $.proxy(handler, this));

    var $span = $("<span>")
        .addClass(css)
        .append($link)
        .on("click", function(e) {
            if($(e.target).is("a")) {
                return;
            }

            e.preventDefault();
            $link.trigger("click");
        });

    return $span;
},

이 방식도 잘 돼.

⸻

내가 더 추천하는 건

두 번째 방식 ($link.trigger("click")) 이야.

왜냐면:
	•	기존 a 클릭 로직 그대로 재사용
	•	handler 직접 호출보다 안전
	•	혹시 a click 쪽에 나중에 로직 추가돼도 span도 같이 따라감

즉 추천 최종본은 이거:

_createPagerButton: function(text, css, handler) {
    var $link = $("<a>")
        .attr("href", EMPTY_HREF)
        .html(text)
        .on("click", $.proxy(handler, this));

    var $span = $("<span>")
        .addClass(css)
        .append($link)
        .on("click", function(e) {
            if($(e.target).is("a")) {
                return;
            }

            e.preventDefault();
            $link.trigger("click");
        });

    return $span;
},

주의

수정 후엔:
	•	jsgrid.js 저장
	•	브라우저 새로고침
	•	캐시 때문에 안 바뀌면 강력 새로고침(Ctrl+F5)

이렇게 해봐.

원하면 내가 이 수정본에 현재 페이지(active page)는 span 클릭 안 하게 조건까지 넣어줄게.



가능은 한데, 원본 수정이면 페이저 만드는 부분을 건드리면 돼.
jsGrid 1.5.3에는 pagerRenderer 옵션이 이미 있고, 이슈 답변에서도 내부 private 함수 _createPagerByFormat() 를 언급해. 즉 페이저 HTML을 만드는 핵심은 그쪽이야.  ￼

네가 jsgrid.js를 직접 수정하겠다면, 압축본 말고 jsgrid.js 원본에서 아래 문자열로 검색해:
	•	pagerRenderer
	•	_createPagerByFormat
	•	pageButtonCount
	•	pagerFormat

보통 수정 포인트는 이 흐름이야.

어디를 손대면 되나
	1.	페이저 전체를 만드는 함수
	•	보통 _createPager() 또는 _createPagerByFormat() 근처
	2.	페이지 번호 한 개를 만드는 부분
	•	여기서 <span> ... <a>1</a> ... </span> 같은 구조가 만들어짐
	3.	그 페이지 번호 span 생성 직후에 클릭 이벤트를 붙이면 돼

즉, 코드 구조가 대략 이런 부분일 거야:

// 페이지 번호 span 생성
var $page = $("<span>").addClass(this.pagerPageClass);

// 내부 a 생성
var $link = $("<a>").attr("href", "#").text(pageIndex);

// 원래는 a에만 클릭이 걸려 있음
$link.on("click", function(e) {
    e.preventDefault();
    // 페이지 이동 처리
});

여기서 네가 추가할 건 span 클릭 시 내부 a와 같은 동작이야.

수정 방식

가장 안전한 직접수정 형태는 이런 느낌이야:

$page.on("click", function(e) {
    if($(e.target).is("a")) {
        return;
    }

    e.preventDefault();
    $link.trigger("click");
});

이걸 페이지 번호 하나를 만드는 자리에 넣으면:
	•	숫자 링크 <a> 눌러도 원래처럼 동작
	•	그 바깥 <span> 눌러도 같은 동작

정리하면 수정할 위치

jsgrid.js에서 페이저 렌더링 쪽, 특히:
	•	_createPagerByFormat()
	•	또는 그 안에서 페이지 번호 element를 만드는 helper 부분

을 찾고,
페이지 번호용 span과 a를 같이 만드는 코드 바로 아래에 span 클릭 핸들러를 추가하면 돼. _createPagerByFormat()이 pager 생성 핵심이라는 건 jsGrid 이슈 답변에도 나온다.  ￼

더 나은 방법

솔직히는 원본 수정 말고, 전에 말한 것처럼 바깥에서:

$(document).on("click", ".jsgrid-pager span", function (e) {
    if ($(e.target).is("a")) return;
    $(this).find("a").first().trigger("click");
});

이걸 붙이는 게 유지보수는 훨씬 좋아.
jsGrid는 pagerRenderer로 커스텀 pager를 만들 수 있게 열어둔 라이브러리라, 원본 수정은 최후 수단으로 보는 게 맞아.  ￼

네 jsgrid.js에서 페이저 만드는 함수 부분 코드 20~30줄만 붙여주면, 내가 정확히 어느 줄 아래에 넣으면 되는지 바로 찍어줄 수 있어.