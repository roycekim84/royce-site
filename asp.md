좋아. 기존 <select> 그대로 두고, jQuery로 타이핑 검색 붙이는 방식으로 가면 돼.

이 방식은:
	•	디자인 거의 안 바뀜
	•	select 그대로 submit 됨
	•	별도 라이브러리 없음
	•	select에 포커스 두고 타이핑하면 일치 항목으로 이동

다만 한계도 있어:
	•	진짜 입력창이 생기는 건 아님
	•	사용자가 친 글자가 박스에 보이진 않음
	•	“검색형 콤보박스”처럼 완전한 UX는 아님

그래도 기존 select 유지 목적에는 제일 잘 맞아.

예시 HTML

<select id="userId" name="userId" class="form-control">
    <option value="">선택하세요</option>
    <option value="1">홍길동</option>
    <option value="2">김철수</option>
    <option value="3">이영희</option>
    <option value="4">박민수</option>
    <option value="5">최수진</option>
    <option value="6">김민지</option>
</select>

jQuery 코드

$(function () {
    var $select = $('#userId');
    var searchText = '';
    var searchTimer = null;
    var resetDelay = 800; // 마지막 입력 후 0.8초 지나면 검색어 초기화

    $select.on('keydown', function (e) {
        // 방향키, 탭, 엔터 등은 기본 동작 유지
        if (
            e.key === 'ArrowUp' ||
            e.key === 'ArrowDown' ||
            e.key === 'ArrowLeft' ||
            e.key === 'ArrowRight' ||
            e.key === 'Tab' ||
            e.key === 'Enter' ||
            e.key === 'Escape'
        ) {
            return;
        }

        // 백스페이스 처리
        if (e.key === 'Backspace') {
            searchText = searchText.slice(0, -1);
            e.preventDefault();
        }
        // 일반 문자만 누적
        else if (e.key.length === 1 && !e.ctrlKey && !e.altKey && !e.metaKey) {
            searchText += e.key.toLowerCase();
            e.preventDefault();
        } else {
            return;
        }

        clearTimeout(searchTimer);
        searchTimer = setTimeout(function () {
            searchText = '';
        }, resetDelay);

        if (!searchText) {
            return;
        }

        var matchedValue = null;

        $select.find('option').each(function () {
            var text = $.trim($(this).text()).toLowerCase();

            // 포함 검색
            if (text.indexOf(searchText) > -1) {
                matchedValue = $(this).val();
                return false; // break
            }
        });

        if (matchedValue !== null) {
            $select.val(matchedValue).trigger('change');
        }
    });

    // select에서 포커스 빠지면 검색어 초기화
    $select.on('blur', function () {
        searchText = '';
        clearTimeout(searchTimer);
    });
});

동작 방식

예를 들어 select에 포커스 두고:
	•	김 치면 김철수
	•	이어서 바로 민 치면 김민지
	•	잠깐 멈췄다가 다시 치면 새 검색 시작

“포함 검색” 말고 “앞글자 검색”으로 바꾸고 싶으면

이 부분:

if (text.indexOf(searchText) > -1)

를 이렇게 바꾸면 돼:

if (text.indexOf(searchText) === 0)

그러면:
	•	김 → 김철수, 김민지 같은 앞글자 일치만 찾음
	•	중간 포함은 안 찾음

여러 select에 공통 적용 버전

같은 기능을 여러 군데 붙일 거면 이렇게 함수로 빼는 게 편해.

function enableSelectTypeSearch(selector) {
    $(selector).each(function () {
        var $select = $(this);
        var searchText = '';
        var searchTimer = null;
        var resetDelay = 800;

        $select.on('keydown', function (e) {
            if (
                e.key === 'ArrowUp' ||
                e.key === 'ArrowDown' ||
                e.key === 'ArrowLeft' ||
                e.key === 'ArrowRight' ||
                e.key === 'Tab' ||
                e.key === 'Enter' ||
                e.key === 'Escape'
            ) {
                return;
            }

            if (e.key === 'Backspace') {
                searchText = searchText.slice(0, -1);
                e.preventDefault();
            }
            else if (e.key.length === 1 && !e.ctrlKey && !e.altKey && !e.metaKey) {
                searchText += e.key.toLowerCase();
                e.preventDefault();
            }
            else {
                return;
            }

            clearTimeout(searchTimer);
            searchTimer = setTimeout(function () {
                searchText = '';
            }, resetDelay);

            if (!searchText) {
                return;
            }

            var matchedValue = null;

            $select.find('option').each(function () {
                var text = $.trim($(this).text()).toLowerCase();

                if (text.indexOf(searchText) > -1) {
                    matchedValue = $(this).val();
                    return false;
                }
            });

            if (matchedValue !== null) {
                $select.val(matchedValue).trigger('change');
            }
        });

        $select.on('blur', function () {
            searchText = '';
            clearTimeout(searchTimer);
        });
    });
}

$(function () {
    enableSelectTypeSearch('#userId');
    // enableSelectTypeSearch('.searchable-select');
});

참고

한글 입력은 브라우저/IME 조합에 따라 keydown에서 애매할 때가 있어서, 한국어 입력 환경에서 아주 빡세게 안정적으로 하려면 composition 계열 이벤트까지 더 다루는 버전이 필요할 수 있어.
그래도 사내 업무 화면에서 간단히 붙여보는 용도로는 위 코드부터 시작하면 충분히 테스트 가능해.

네 <select> 코드에 맞춰서 id 포함해서 바로 붙일 버전으로 바꿔줄 수도 있어.