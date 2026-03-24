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