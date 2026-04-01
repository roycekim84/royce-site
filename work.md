

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