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