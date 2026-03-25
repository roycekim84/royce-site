그건 거의 이런 상황이야.

원래 select에 이미 u-select용 뷰가 붙는 구조인데,
거기에 내가 준 select-new 변환이 한 번 더 별도 UI를 만들어서
결과적으로
	•	기존 u-select가 만든 뷰 1개
	•	select-new-wrap 1개

이렇게 두 개가 같이 보이는 상태야.

즉 문제는 JS 에러가 아니라 중복 렌더링 쪽이야.

왜 그런가

네 말에 나온 u-select가 힌트야. 보통 이런 경우는:

<select class="u-select select-new">

이 select를 기존 프로젝트 CSS/JS가 이미 꾸며서 보여주고 있는데,
내 코드가 또 숨기고 새 input UI를 만들고 있어서 두 시스템이 동시에 작동하는 거야.

⸻

제일 쉬운 해결

1) u-select를 가진 select는 원본을 확실히 숨기기

아래 CSS를 먼저 넣어봐:

select.select-new {
    display: none !important;
}

그리고 wrapper는 보이게:

.select-new-wrap {
    display: inline-block !important;
}

근데 이걸로도 해결 안 되면,
u-select가 select 자체가 아니라 별도 div/span를 생성하는 구조일 가능성이 높아.

⸻

2) 기존 u-select가 만든 뷰를 같이 숨겨야 함

개발자도구로 보면 select 옆에 뭔가 이런 게 붙어 있을 거야:
	•	.u-select
	•	.u-select-box
	•	.u-select-wrap
	•	.selectric
	•	.chosen-container
	•	뭔가 별도 wrapper

즉 DOM이 대충 이렇게 되어 있을 수 있어:

<select class="u-select select-new">...</select>
<div class="u-select-rendered">...</div>
<div class="select-new-wrap">...</div>

이러면 select만 숨겨서는 안 되고,
기존 u-select 렌더링 div도 숨겨야 해.

⸻

바로 넣어볼 수정 JS

내가 준 코드에서 이 부분 추가해봐.

$(function () {
    $('.select-new').each(function () {
        var $select = $(this);

        if ($select.data('select-new-applied')) {
            return;
        }
        $select.data('select-new-applied', true);

        // 기존 u-select 류 커스텀 뷰 숨기기 시도
        $select.hide();

        $select.next('.u-select').hide();
        $select.next('.u-select-wrap').hide();
        $select.next('.u-select-box').hide();
        $select.next('.selectric-wrapper').hide();
        $select.next('.chosen-container').hide();

        var selectWidth = $select.outerWidth();
        var placeholder = '';
        var currentValue = $select.val();

        var $firstOption = $select.find('option').first();
        if ($firstOption.length && ($firstOption.val() === '' || $firstOption.val() == null)) {
            placeholder = $.trim($firstOption.text());
        }

        var $wrap = $('<div class="select-new-wrap"></div>');
        var $input = $('<input type="text" class="select-new-input" autocomplete="off" />');
        var $arrow = $('<div class="select-new-arrow"></div>');
        var $list = $('<ul class="select-new-list"></ul>');

        if (selectWidth) {
            $wrap.css('max-width', selectWidth + 'px');
        }

        if (placeholder) {
            $input.attr('placeholder', placeholder);
        }

        $select.find('option').each(function () {
            var $option = $(this);
            var value = $option.val();
            var text = $.trim($option.text());

            var $li = $('<li></li>')
                .attr('data-value', value)
                .attr('data-text', text)
                .text(text);

            $list.append($li);
        });

        $wrap.append($input).append($arrow).append($list);
        $select.after($wrap);

        var activeIndex = -1;

        function getVisibleItems() {
            return $list.find('li:visible');
        }

        function openList() {
            $list.show();
        }

        function closeList() {
            $list.hide();
            activeIndex = -1;
            $list.find('li').removeClass('active');
        }

        function filterList(keyword) {
            var text = $.trim(keyword).toLowerCase();
            var visibleCount = 0;

            $list.find('li').each(function () {
                var $li = $(this);
                var itemText = ($li.attr('data-text') || '').toLowerCase();

                if (!text || itemText.indexOf(text) > -1) {
                    $li.show();
                    visibleCount++;
                } else {
                    $li.hide();
                }
            });

            if (visibleCount > 0) openList();
            else closeList();
        }

        function syncSelect(value, text) {
            $select.val(value).trigger('change');
            $input.val(text);
        }

        function selectItem($item) {
            if (!$item.length) return;
            syncSelect($item.attr('data-value'), $item.attr('data-text'));
            closeList();
        }

        function setActive(direction) {
            var $visible = getVisibleItems();
            if (!$visible.length) return;

            if (direction === 'down') {
                activeIndex = (activeIndex + 1) % $visible.length;
            } else {
                activeIndex = (activeIndex - 1 + $visible.length) % $visible.length;
            }

            $list.find('li').removeClass('active');
            $visible.eq(activeIndex).addClass('active');
        }

        function applyInitialValue() {
            var $selectedOption = $select.find('option:selected');
            if ($selectedOption.length && $selectedOption.val()) {
                $input.val($.trim($selectedOption.text()));
            }
        }

        applyInitialValue();

        $input.on('focus click', function () {
            filterList($input.val());
        });

        $input.on('input', function () {
            activeIndex = -1;
            filterList($(this).val());

            if ($(this).val() === '') {
                $select.val('').trigger('change');
            }
        });

        $input.on('keydown', function (e) {
            if (e.key === 'ArrowDown') {
                e.preventDefault();
                openList();
                setActive('down');
            } else if (e.key === 'ArrowUp') {
                e.preventDefault();
                openList();
                setActive('up');
            } else if (e.key === 'Enter') {
                var $active = $list.find('li.active:visible');
                if ($active.length) {
                    e.preventDefault();
                    selectItem($active);
                }
            } else if (e.key === 'Escape') {
                closeList();
            }
        });

        $list.on('click', 'li', function () {
            selectItem($(this));
        });

        $(document).on('click.selectNew', function (e) {
            if (!$(e.target).closest($wrap).length) {
                closeList();
            }
        });

        $select.on('change', function () {
            var $selectedOption = $select.find('option:selected');
            if ($selectedOption.length && $selectedOption.val()) {
                $input.val($.trim($selectedOption.text()));
            } else {
                $input.val('');
            }
        });
    });
});


⸻

더 가능성 큰 진짜 원인

네 프로젝트에 이미 이런 코드가 있을 가능성이 높아:

$('.u-select').something();

혹은 공통 스크립트가 페이지 로드 때 select를 꾸며버림.

그러면 네 select가

<select class="u-select select-new">

일 때,
기존 공통 스크립트가 먼저 먹고,
그 다음 select-new가 또 먹어서 겹쳐.

이럴 때 제일 깔끔한 해결

u-select는 빼고 select-new만 붙여서 테스트 해봐.

즉:

<select class="select-new">

이걸로 했을 때 하나만 보이면 원인 확정이야.

⸻

추천 방식

방법 A

기존 u-select 쓰는 화면이면
그 요소에는 select-new를 같이 쓰지 말고,
아예 별도 클래스로 분리

방법 B

select-new를 적용할 때 기존 u-select 클래스를 제거

예:

$select.removeClass('u-select');

이걸 변환 전에 넣기

⸻

아주 빠른 확인법

개발자도구에서 해당 부분 DOM 보면 아마 이런 식일 거야:
	•	원래 <select>
	•	u-select가 만든 wrapper
	•	select-new-wrap

이 3개 중 2개가 동시에 보일 거다.

⸻

제일 짧은 결론

지금은 select-new 문제라기보다 기존 u-select 커스텀과 충돌하는 거야.
가장 먼저 해볼 건:
	1.	class="u-select select-new"면 u-select 빼고 테스트
	2.	안 되면 select.select-new { display:none !important; }
	3.	그래도 남으면 기존 u-select가 생성한 wrapper를 숨기기

네 실제 HTML 한 줄, 예를 들면

<select class="u-select select-new form-control" ...>

이런 거랑, 개발자도구에서 생성된 바로 아래 DOM 3~4줄만 주면 내가 정확히 어느 놈을 숨겨야 하는지 바로 찍어줄게.


좋아. 그럼 <select class="select-new">를 자동으로 검색형으로 바꾸는 방식으로 깔끔하게 줄게.

이 방식 특징:
	•	기존 <select> 그대로 사용
	•	class="select-new" 붙은 것만 변환
	•	jQuery만 사용
	•	텍스트 입력 보임
	•	검색 가능
	•	기존 select 값도 유지해서 form submit 그대로 됨
	•	디자인은 네가 CSS로 더 다듬으면 됨

⸻

1) HTML 사용 방식

기존 select에 클래스만 붙이면 돼.

<select id="userId" name="userId" class="form-control select-new">
    <option value="">선택하세요</option>
    <option value="1">홍길동</option>
    <option value="2">김철수</option>
    <option value="3">이영희</option>
    <option value="4">박민수</option>
    <option value="5">최수진</option>
</select>

여러 개 있어도 다 적용 가능:

<select id="deptId" name="deptId" class="form-control select-new">
    <option value="">부서를 선택하세요</option>
    <option value="10">개발팀</option>
    <option value="20">기획팀</option>
    <option value="30">운영팀</option>
</select>


⸻

2) CSS

아래 화살표는 네가 원한 선형 chevron으로 넣어뒀어.

.select-new-wrap {
    position: relative;
    display: inline-block;
    width: 100%;
    max-width: 300px;
}

.select-new-origin {
    display: none !important;
}

.select-new-input {
    width: 100%;
    height: 34px;
    padding: 6px 30px 6px 12px;
    border: 1px solid #ccc;
    border-radius: 4px;
    box-sizing: border-box;
    background-color: #fff;
    outline: none;
}

.select-new-input:focus {
    border-color: #66afe9;
}

.select-new-arrow {
    position: absolute;
    top: 50%;
    right: 12px;
    width: 10px;
    height: 10px;
    transform: translateY(-60%);
    pointer-events: none;
}

.select-new-arrow::before,
.select-new-arrow::after {
    content: "";
    position: absolute;
    top: 4px;
    width: 7px;
    height: 1.5px;
    background: #666;
}

.select-new-arrow::before {
    left: 0;
    transform: rotate(45deg);
}

.select-new-arrow::after {
    right: 0;
    transform: rotate(-45deg);
}

.select-new-list {
    position: absolute;
    top: calc(100% + 2px);
    left: 0;
    right: 0;
    max-height: 220px;
    margin: 0;
    padding: 0;
    list-style: none;
    border: 1px solid #ccc;
    border-radius: 4px;
    background: #fff;
    overflow-y: auto;
    display: none;
    z-index: 9999;
    box-sizing: border-box;
}

.select-new-list li {
    padding: 8px 12px;
    cursor: pointer;
}

.select-new-list li:hover,
.select-new-list li.active {
    background: #f2f2f2;
}


⸻

3) jQuery

이게 핵심이야.

$(function () {
    $('.select-new').each(function () {
        var $select = $(this);

        if ($select.data('select-new-applied')) {
            return;
        }
        $select.data('select-new-applied', true);

        var selectWidth = $select.outerWidth();
        var placeholder = '';
        var currentValue = $select.val();

        var $firstOption = $select.find('option').first();
        if ($firstOption.length && ($firstOption.val() === '' || $firstOption.val() == null)) {
            placeholder = $.trim($firstOption.text());
        }

        var $wrap = $('<div class="select-new-wrap"></div>');
        var $input = $('<input type="text" class="select-new-input" autocomplete="off" />');
        var $arrow = $('<div class="select-new-arrow"></div>');
        var $list = $('<ul class="select-new-list"></ul>');

        if (selectWidth) {
            $wrap.css('max-width', selectWidth + 'px');
        }

        if (placeholder) {
            $input.attr('placeholder', placeholder);
        }

        $select.find('option').each(function () {
            var $option = $(this);
            var value = $option.val();
            var text = $.trim($option.text());

            var $li = $('<li></li>')
                .attr('data-value', value)
                .attr('data-text', text)
                .text(text);

            $list.append($li);
        });

        $select.addClass('select-new-origin');
        $select.after($wrap);
        $wrap.append($input).append($arrow).append($list);

        var activeIndex = -1;

        function getVisibleItems() {
            return $list.find('li:visible');
        }

        function openList() {
            $list.show();
        }

        function closeList() {
            $list.hide();
            activeIndex = -1;
            $list.find('li').removeClass('active');
        }

        function filterList(keyword) {
            var text = $.trim(keyword).toLowerCase();
            var visibleCount = 0;

            $list.find('li').each(function () {
                var $li = $(this);
                var itemText = ($li.attr('data-text') || '').toLowerCase();

                if (!text || itemText.indexOf(text) > -1) {
                    $li.show();
                    visibleCount++;
                } else {
                    $li.hide();
                }
            });

            if (visibleCount > 0) {
                openList();
            } else {
                closeList();
            }
        }

        function syncSelect(value, text) {
            $select.val(value).trigger('change');
            $input.val(text);
        }

        function selectItem($item) {
            if (!$item || !$item.length) return;

            var value = $item.attr('data-value');
            var text = $item.attr('data-text');

            syncSelect(value, text);
            closeList();
        }

        function setActive(direction) {
            var $visible = getVisibleItems();
            if (!$visible.length) return;

            if (direction === 'down') {
                activeIndex++;
                if (activeIndex >= $visible.length) activeIndex = 0;
            } else if (direction === 'up') {
                activeIndex--;
                if (activeIndex < 0) activeIndex = $visible.length - 1;
            }

            $list.find('li').removeClass('active');
            var $active = $visible.eq(activeIndex);
            $active.addClass('active');

            var listEl = $list.get(0);
            var itemEl = $active.get(0);

            if (listEl && itemEl) {
                var itemTop = itemEl.offsetTop;
                var itemBottom = itemTop + itemEl.offsetHeight;
                var viewTop = listEl.scrollTop;
                var viewBottom = viewTop + listEl.clientHeight;

                if (itemTop < viewTop) {
                    listEl.scrollTop = itemTop;
                } else if (itemBottom > viewBottom) {
                    listEl.scrollTop = itemBottom - listEl.clientHeight;
                }
            }
        }

        function applyInitialValue() {
            var $selectedOption = $select.find('option:selected');
            if ($selectedOption.length) {
                var selectedValue = $selectedOption.val();
                var selectedText = $.trim($selectedOption.text());

                if (selectedValue) {
                    $input.val(selectedText);
                } else {
                    $input.val('');
                }
            }
        }

        applyInitialValue();

        $input.on('focus click', function () {
            filterList($input.val());
        });

        $input.on('input', function () {
            activeIndex = -1;
            filterList($(this).val());

            if ($(this).val() === '') {
                $select.val('').trigger('change');
            }
        });

        $input.on('keydown', function (e) {
            if (e.key === 'ArrowDown') {
                e.preventDefault();
                openList();
                setActive('down');
            } else if (e.key === 'ArrowUp') {
                e.preventDefault();
                openList();
                setActive('up');
            } else if (e.key === 'Enter') {
                var $active = $list.find('li.active:visible');
                if ($active.length) {
                    e.preventDefault();
                    selectItem($active);
                }
            } else if (e.key === 'Escape') {
                closeList();
            }
        });

        $list.on('click', 'li', function () {
            selectItem($(this));
        });

        $(document).on('click.selectNew', function (e) {
            if (!$(e.target).closest($wrap).length) {
                closeList();
            }
        });

        $select.on('change', function () {
            var $selectedOption = $select.find('option:selected');
            var selectedValue = $selectedOption.val();
            var selectedText = $.trim($selectedOption.text());

            if (selectedValue) {
                $input.val(selectedText);
            } else {
                $input.val('');
            }
        });
    });
});


⸻

4) 동작 방식

이 코드는 이렇게 움직여:
	•	원래 select.select-new는 숨김
	•	대신 같은 자리에 검색 input + 리스트 생성
	•	사용자가 input에 타이핑하면 option 텍스트 기준 필터링
	•	항목 클릭하면 원래 select 값도 같이 바뀜
	•	form submit 시에는 원래 select가 name/value를 가지고 있으니 그대로 전송됨

즉, 서버 코드는 거의 안 건드려도 돼.

⸻

5) Razor에서도 그대로 가능

DB에서 option을 렌더링하고 있어도 상관없어.

<select id="userId" name="userId" class="form-control select-new">
    <option value="">선택하세요</option>
    @foreach (var item in Model.UserList)
    {
        <option value="@item.Value">@item.Text</option>
    }
</select>

이렇게만 해두면 위 jQuery가 자동 변환해.

⸻

6) 포함 검색 말고 앞글자 검색으로 바꾸고 싶으면

이 부분:

if (!text || itemText.indexOf(text) > -1)

를 이렇게 바꾸면 돼:

if (!text || itemText.indexOf(text) === 0)


⸻

7) 나중에 동적으로 option 바뀌는 경우

AJAX로 select option을 갈아끼우는 화면이면, 바꾼 뒤에 다시 렌더링 함수 호출 구조로 조금 손봐야 해.
지금 버전은 초기 페이지 로드 시점의 option 기준이야.

⸻

8) 실무 팁

.form-control 스타일을 최대한 유지하고 싶으면 .select-new-input에 부트스트랩 비슷한 높이, 패딩, border-radius를 맞추면 거의 티 안 나게 갈 수 있어.

원하면 다음 답변에서 내가 이걸 함수형으로 빼서 initSelectNew() 한 번만 호출하면 되게 정리해줄게.




그 요구사항이면 결론이 있어:

진짜 기본 <select> 자체로는
	•	입력한 텍스트를 박스 안에 보이게 하면서
	•	검색까지 되는 형태
를 만들기 어렵다.

왜냐면 네이티브 select는 입력창이 아니어서 사용자가 친 텍스트를 표시하는 UI를 직접 제어할 수 없거든.

그래서 라이브러리 없이 jQuery만 쓴다면, 제일 현실적인 방법은:

“겉모습은 select 비슷하게 보이는 input + dropdown”을 만들고,
실제 값 전송은 hidden/select에 동기화 하는 방식이야.

이게 Select2처럼 디자인이 확 바뀌진 않고, 네가 CSS를 최소한으로만 주면 기존 select 느낌 최대한 비슷하게 갈 수 있어.

아래는 jQuery만 사용한 완성형 예시야.

⸻

1) HTML

<div class="searchable-select" id="userSearchBox">
    <input type="text" id="userSearchInput" class="searchable-select-input" placeholder="선택하세요" autocomplete="off" />
    <input type="hidden" id="userId" name="userId" />

    <div class="searchable-select-arrow">▼</div>

    <ul class="searchable-select-list" id="userSearchList">
        <li data-value="1">홍길동</li>
        <li data-value="2">김철수</li>
        <li data-value="3">이영희</li>
        <li data-value="4">박민수</li>
        <li data-value="5">최수진</li>
        <li data-value="6">김민지</li>
        <li data-value="7">오세훈</li>
    </ul>
</div>


⸻

2) CSS

기존 select 느낌에 최대한 가깝게 아주 무난하게 잡은 버전이야.

.searchable-select {
    position: relative;
    width: 280px;
    font-size: 14px;
}

.searchable-select-input {
    width: 100%;
    height: 34px;
    padding: 6px 32px 6px 12px;
    border: 1px solid #ccc;
    border-radius: 4px;
    box-sizing: border-box;
    outline: none;
}

.searchable-select-input:focus {
    border-color: #66afe9;
}

.searchable-select-arrow {
    position: absolute;
    top: 50%;
    right: 10px;
    transform: translateY(-50%);
    pointer-events: none;
    font-size: 12px;
    color: #666;
}

.searchable-select-list {
    position: absolute;
    top: 100%;
    left: 0;
    right: 0;
    max-height: 220px;
    margin: 2px 0 0 0;
    padding: 0;
    list-style: none;
    border: 1px solid #ccc;
    border-radius: 4px;
    background: #fff;
    overflow-y: auto;
    display: none;
    z-index: 9999;
    box-sizing: border-box;
}

.searchable-select-list li {
    padding: 8px 12px;
    cursor: pointer;
}

.searchable-select-list li:hover,
.searchable-select-list li.active {
    background: #f2f2f2;
}


⸻

3) jQuery

$(function () {
    var $box = $('#userSearchBox');
    var $input = $('#userSearchInput');
    var $list = $('#userSearchList');
    var $hidden = $('#userId');
    var $items = $list.find('li');
    var activeIndex = -1;

    console.log('초기화 시작');
    console.log('item count:', $items.length);

    function openList() {
        console.log('목록 열기');
        $list.show();
    }

    function closeList() {
        console.log('목록 닫기');
        $list.hide();
        activeIndex = -1;
        $items.removeClass('active');
    }

    function filterList(keyword) {
        var text = $.trim(keyword).toLowerCase();
        var visibleCount = 0;

        console.log('filter keyword:', text);

        $items.each(function () {
            var $li = $(this);
            var itemText = $.trim($li.text()).toLowerCase();

            if (itemText.indexOf(text) > -1) {
                $li.show();
                visibleCount++;
            } else {
                $li.hide();
            }
        });

        console.log('visibleCount:', visibleCount);

        if (visibleCount > 0) {
            openList();
        } else {
            closeList();
        }
    }

    function setActiveVisibleItem(direction) {
        var $visibleItems = $items.filter(':visible');

        if ($visibleItems.length === 0) {
            console.log('보이는 항목 없음');
            return;
        }

        if (direction === 'down') {
            activeIndex++;
            if (activeIndex >= $visibleItems.length) {
                activeIndex = 0;
            }
        } else if (direction === 'up') {
            activeIndex--;
            if (activeIndex < 0) {
                activeIndex = $visibleItems.length - 1;
            }
        }

        $items.removeClass('active');
        var $activeItem = $visibleItems.eq(activeIndex);
        $activeItem.addClass('active');

        console.log('active item:', $activeItem.text());

        var listEl = $list.get(0);
        var itemEl = $activeItem.get(0);

        if (listEl && itemEl) {
            var itemTop = itemEl.offsetTop;
            var itemBottom = itemTop + itemEl.offsetHeight;
            var viewTop = listEl.scrollTop;
            var viewBottom = viewTop + listEl.clientHeight;

            if (itemTop < viewTop) {
                listEl.scrollTop = itemTop;
            } else if (itemBottom > viewBottom) {
                listEl.scrollTop = itemBottom - listEl.clientHeight;
            }
        }
    }

    function selectItem($item) {
        if (!$item || $item.length === 0) return;

        var value = $item.data('value');
        var text = $.trim($item.text());

        console.log('선택됨:', value, text);

        $input.val(text);
        $hidden.val(value).trigger('change');
        closeList();
    }

    $input.on('focus click', function () {
        console.log('input focus/click');
        filterList($input.val());
    });

    $input.on('input', function () {
        console.log('input event:', $(this).val());
        activeIndex = -1;
        filterList($(this).val());

        if ($(this).val() === '') {
            $hidden.val('');
            console.log('hidden value 초기화');
        }
    });

    $input.on('keydown', function (e) {
        console.log('keydown:', e.key);

        if (e.key === 'ArrowDown') {
            e.preventDefault();
            openList();
            setActiveVisibleItem('down');
        }
        else if (e.key === 'ArrowUp') {
            e.preventDefault();
            openList();
            setActiveVisibleItem('up');
        }
        else if (e.key === 'Enter') {
            var $visibleActive = $items.filter(':visible.active');
            if ($visibleActive.length > 0) {
                e.preventDefault();
                selectItem($visibleActive);
            }
        }
        else if (e.key === 'Escape') {
            closeList();
        }
    });

    $items.on('click', function () {
        console.log('li click:', $(this).text());
        selectItem($(this));
    });

    $(document).on('click', function (e) {
        if (!$(e.target).closest('#userSearchBox').length) {
            console.log('바깥 클릭');
            closeList();
        }
    });
});


⸻

4) 동작 방식

이 코드는 이렇게 동작해:
	•	input 클릭하면 목록 열림
	•	글자 입력하면 목록 필터링
	•	클릭해서 선택 가능
	•	방향키 위/아래 이동 가능
	•	Enter로 선택 가능
	•	실제 전송값은 hidden input(name="userId") 에 저장됨

즉 서버에는 기존 select처럼 ID 값이 넘어가고, 화면에는 텍스트가 보이는 검색박스가 보여.

⸻

5) DB 데이터로 렌더링하는 Razor 예시

서버에서 DB 값 뿌리는 구조면 이렇게 바꾸면 돼:

<div class="searchable-select" id="userSearchBox">
    <input type="text" id="userSearchInput" class="searchable-select-input" placeholder="선택하세요" autocomplete="off" />
    <input type="hidden" id="userId" name="userId" value="@Model.UserId" />

    <div class="searchable-select-arrow">▼</div>

    <ul class="searchable-select-list" id="userSearchList">
        @foreach (var item in Model.UserList)
        {
            <li data-value="@item.Value">@item.Text</li>
        }
    </ul>
</div>


⸻

6) 수정 포인트

포함 검색 → 앞글자 검색으로 바꾸기

지금은 포함 검색이야:

if (itemText.indexOf(text) > -1)

앞에서 시작하는 것만 찾고 싶으면:

if (itemText.indexOf(text) === 0)


⸻

초기 선택값 표시

수정 화면처럼 이미 값이 있으면, 페이지 로드시 텍스트도 채워줘야 해. 그 버전도 붙일 수 있어.

예를 들면 hidden 값 기준으로 li 찾아서 input 채움.

⸻

가능해.
삼각형 ▼ 대신 선 두 개로 만든 아래 화살표(chevron) 쓰면 돼.

예를 들면 HTML은 이렇게 비워두고:

<div class="searchable-select-arrow"></div>

CSS를 이렇게 주면 돼:

.searchable-select-arrow {
    position: absolute;
    top: 50%;
    right: 12px;
    width: 10px;
    height: 10px;
    transform: translateY(-60%);
    pointer-events: none;
}

.searchable-select-arrow::before,
.searchable-select-arrow::after {
    content: "";
    position: absolute;
    top: 4px;
    width: 7px;
    height: 1.5px;
    background: #666;
}

.searchable-select-arrow::before {
    left: 0;
    transform: rotate(45deg);
}

.searchable-select-arrow::after {
    right: 0;
    transform: rotate(-45deg);
}

이렇게 하면 > 같은 선 느낌으로 만든 아래 방향 꺾쇠 화살표가 나와.

더 얇고 깔끔하게 하고 싶으면:
	•	height: 1px;
	•	background: #777;
	•	width: 6px;

이런 식으로 조절하면 되고,

좀 더 또렷하게 하려면:
	•	height: 2px;
	•	background: #555;

로 바꾸면 돼.

참고로 지금 방향이 이상하면 rotate 각도만 바꾸면 돼:
	•	아래 화살표: 45deg, -45deg
	•	위 화살표: -45deg, 45deg

원하면 내가 네 현재 CSS 기준으로 딱 어울리는 chevron 화살표 스타일 한 버전 더 정리해줄게.




7) 솔직한 결론

네 요구사항을 정확히 만족시키려면
기본 native select 그대로는 어렵고,
select처럼 보이는 검색 input + dropdown 으로 가야 해.

이게 라이브러리 없이 jQuery만으로 구현하는 가장 자연스러운 방법이야.

지금 네가 쓰는 실제 DB 바인딩된 select 코드 붙여주면, 그 구조 그대로 내가 바로 변환해서 맞춰줄게.