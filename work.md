돼.
근데 $(tr).val(text)는 row 전체에 쓰는 게 아니라 input 같은 폼 요소에 쓰는 거라서, Kendo Grid 행의 다른 컬럼 값을 바꾸려면 dataItem을 수정하는 방식이 맞아. Kendo Grid의 dataItem(row)는 그 행에 바인딩된 모델을 반환하고, 모델 값은 set(field, value)로 바꾸는 게 정석이야.  ￼

예를 들어 같은 줄의 input 값을 읽고, 같은 행의 다른 컬럼 status를 바꾸려면:

var grid = $("#grid").data("kendoGrid");
var tr = $(this).closest("tr");
var dataItem = grid.dataItem(tr);

var text = tr.find(".grid-text").val();   // 같은 줄 input 값 읽기
dataItem.set("status", text);             // 같은 줄 다른 컬럼 값 변경

이렇게 하면 그리드 데이터도 바뀌고 화면도 반영돼. 반대로 dataItem["status"] = text처럼 직접 대입만 하면 내부 값은 바뀌어도 UI가 바로 안 갱신될 수 있어. Telerik 쪽도 모델 업데이트에는 set 메서드를 쓰라고 안내해.  ￼

자주 쓰는 패턴은 이거야:

$(document).on("click", ".some-btn", function () {
    var grid = $("#grid").data("kendoGrid");
    var tr = $(this).closest("tr");
    var dataItem = grid.dataItem(tr);

    var text = tr.find(".grid-text-click").val();

    dataItem.set("message", text);
    dataItem.set("otherField", "변경값");
});

정리하면:
	•	input 값 읽기: tr.find(".클래스").val()
	•	같은 행 다른 컬럼 변경: dataItem.set("필드명", 값)

그리고 네가 이미 attr로 값 읽고 있었다면 그것도 같이 가능해:

var text = tr.find(".grid-text-click").attr("data-message");
dataItem.set("message", text);

한 줄 결론:
가능하고, Kendo Grid에서는 같은 행의 다른 컬럼을 바꾸려면 grid.dataItem(tr).set("필드명", 값)으로 바꾸는 게 맞아.