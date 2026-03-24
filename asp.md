<select id="deptCd" name="deptCd" class="form-control">
    <option value="">선택하세요</option>
    @foreach (var item in Model.DeptList)
    {
        <option value="@item.Code">@item.Name</option>
    }
</select>

<script>
    $(function () {
        $('#deptCd').select2({
            placeholder: '선택하세요',
            allowClear: true,
            width: '100%'
        });
    });
</script>



<link href="https://cdn.jsdelivr.net/npm/select2@4.1.0-rc.0/dist/css/select2.min.css" rel="stylesheet" />
<script src="https://code.jquery.com/jquery-3.6.0.min.js"></script>
<script src="https://cdn.jsdelivr.net/npm/select2@4.1.0-rc.0/dist/js/select2.min.js"></script>

<script>
    $(function () {
        $('#userId').select2({
            placeholder: '선택하세요',
            allowClear: true,
            width: '100%'
        });
    });
</script>




응, 옵션 있어. 그리고 헷갈리기 쉬운 포인트가 하나 있어.

Select2는 “닫힌 상태의 박스에 바로 타이핑”하는 방식이 아니라, 보통 먼저 드롭다운을 열고 그 안의 검색칸에 입력하는 방식이야. 기본 사용 문서도 Select2를 기존 <select> 대체 UI로 설명하고, 검색 관련 문서도 검색창이 드롭다운 내부에 표시되는 흐름으로 설명해.  ￼

그래서 먼저 이것부터 확인해봐:

$('#userId').select2({
    width: '100%'
});

이 상태에서
	1.	셀렉트 클릭
	2.	드롭다운 열림
	3.	위쪽 검색칸에 타이핑

이게 기본 동작이야.
만약 검색칸 자체가 안 보이면 minimumResultsForSearch 설정 영향일 수 있어. Select2 공식 문서에 따르면 이 옵션이 검색창 표시 여부를 제어하고, Infinity면 숨겨져.  ￼

검색창을 확실히 보이게 하려면 이렇게 해:

$('#userId').select2({
    width: '100%',
    minimumResultsForSearch: 0
});

반대로 이런 코드가 있으면 검색창이 숨겨져:

minimumResultsForSearch: Infinity

이건 공식 문서에 나온 숨김 방식이야.  ￼

또 하나는 최소 입력 글자 수 옵션이야.
minimumInputLength를 넣어두면 그 글자 수 이상 입력해야 검색이 시작돼. 공식 옵션 문서에 있어.  ￼

예:

$('#userId').select2({
    width: '100%',
    minimumResultsForSearch: 0,
    minimumInputLength: 1
});

그런데 네 증상이 “검색칸은 보이는데 커서가 안 들어가고 타이핑이 안 먹는다” 쪽이면, 그건 설정 문제가 아니라 포커스 문제일 가능성이 커. Select2 포럼 쪽에서 jQuery 버전, 모달 안에서 사용, label 안에 select가 들어간 구조 때문에 검색 입력창이 포커스를 잃는 사례가 보고돼 있고, 공식 트러블슈팅도 모달에서는 dropdownParent 설정을 권장해.  ￼

그럴 땐 이걸 많이 써:

$('#userId').select2({
    width: '100%'
});

$(document).on('select2:open', function () {
    document.querySelector('.select2-container--open .select2-search__field').focus();
});

모달 안이면:

$('#userId').select2({
    width: '100%',
    dropdownParent: $('#myModal')
});

그리고 HTML이 이런 식이면:

<label>
    사용자
    <select id="userId">...</select>
</label>

이 구조도 포커스 문제를 만들 수 있어서, 포럼에서는 label 밖으로 select를 빼면 해결된 사례가 있어.  ￼

제일 먼저 체크할 건 딱 4개야.
	1.	드롭다운 열었을 때 검색칸이 보이는지
	2.	minimumResultsForSearch: Infinity 같은 게 있는지
	3.	모달 안에서 쓰는지
	4.	select가 label 안에 들어가 있는지

제일 무난한 기본형은 이거야:

$('#userId').select2({
    width: '100%',
    minimumResultsForSearch: 0
});

$(document).on('select2:open', function () {
    const input = document.querySelector('.select2-container--open .select2-search__field');
    if (input) input.focus();
});

네 select2() 초기화 코드랑 해당 <select> HTML 한 덩어리 붙여주면 어디가 막히는지 바로 짚어줄 수 있어.