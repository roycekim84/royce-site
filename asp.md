<input type="text" id="searchBox" placeholder="검색어 입력">

<select id="mySelect" size="5">
  <option>Apple</option>
  <option>Banana</option>
  <option>Orange</option>
  <option>Grape</option>
  <option>Pineapple</option>
</select>

<script>
const searchBox = document.getElementById("searchBox");
const select = document.getElementById("mySelect");
const allOptions = Array.from(select.options).map(option => option.text);

searchBox.addEventListener("input", function () {
  const keyword = this.value.toLowerCase();

  select.innerHTML = "";

  allOptions
    .filter(text => text.toLowerCase().includes(keyword))
    .forEach(text => {
      const option = document.createElement("option");
      option.text = text;
      select.add(option);
    });
});
</script>