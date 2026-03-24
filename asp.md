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

7) 솔직한 결론

네 요구사항을 정확히 만족시키려면
기본 native select 그대로는 어렵고,
select처럼 보이는 검색 input + dropdown 으로 가야 해.

이게 라이브러리 없이 jQuery만으로 구현하는 가장 자연스러운 방법이야.

지금 네가 쓰는 실제 DB 바인딩된 select 코드 붙여주면, 그 구조 그대로 내가 바로 변환해서 맞춰줄게.