좋아. 그럼 제일 깔끔하게 이렇게 가면 돼:
	•	기본 u-select는 지금처럼 그대로 동작
	•	특정 select에만 예를 들어 u-select-search 클래스를 추가하면
	•	그때만 input 검색 가능
	•	클래스 없으면
	•	기존 div toggle 방식 유지

즉 사용법은 이렇게:

<select class="u-select-target">

기본형

<select class="u-select-target u-select-search">

검색형

이 방식으로 만들면 돼.

아래는 기존 코드 최대한 유지하면서,
u-select-search 클래스가 있을 때만 검색형 input 으로 바뀌는 버전이야.

// ========== 커스텀 셀렉트 (기본/검색형 겸용) ==========
(function ($) {
  function closeAll() {
    $(".u-select.open").each(function () {
      var $wrap = $(this);
      $wrap.removeClass("open").attr("aria-expanded", "false");

      var $container = $wrap.closest(".search-wrap");
      if ($container.length) {
        if ($container.find(".u-select.open").length === 0) {
          $container.removeClass("has-open-dropdown");
        }
      }
    });
  }

  $.fn.upgradeSelectToDropdown = function () {
    return this.each(function () {
      var $select = $(this);
      if ($select.data("upgraded")) return;
      $select.data("upgraded", true);

      var isSearchable = $select.hasClass("u-select-search");

      var $wrap = $(
        '<div class="u-select" role="combobox" aria-expanded="false" style="margin-top: 5px;"></div>'
      );

      var $toggle;
      if (isSearchable) {
        $toggle = $('<input type="text" class="u-select-toggle u-select-input" autocomplete="off" />');
      } else {
        $toggle = $('<div class="u-select-toggle" tabindex="0"></div>');
      }

      var $menu = $('<div class="u-menu" role="listbox"></div>');

      $wrap.append($toggle).append($menu);

      var selectedTextCache = "";

      function render() {
        $menu.empty();
        $select.find("option").each(function () {
          var dis = this.disabled ? ' aria-disabled="true"' : "";
          $menu.append(
            '<div class="u-item" role="option" data-value="' +
              this.value +
              '" data-text="' +
              $('<div>').text($(this).text()).html() +
              '"' +
              dis +
              ">" +
              $(this).text() +
              "</div>"
          );
        });
      }

      function isPlaceholder($opt) {
        return $opt.is("[data-placeholder]") || $.trim($opt.val()) === "";
      }

      function syncSelectedState(val) {
        $menu.find(".u-item").attr("aria-selected", "false");
        $menu.find('.u-item[data-value="' + val + '"]').attr("aria-selected", "true");
      }

      function setDisplayText(text) {
        if (isSearchable) {
          $toggle.val(text);
        } else {
          $toggle.text(text);
        }
      }

      function getDisplayText() {
        return isSearchable ? $toggle.val() : $toggle.text();
      }

      function setByValue(val, fire) {
        var $opt = $select.find('option[value="' + val + '"]');
        if (!$opt.length) $opt = $select.find("option").eq(0);

        selectedTextCache = $.trim($opt.text());
        setDisplayText(selectedTextCache);
        syncSelectedState($opt.val());

        if (isPlaceholder($opt)) {
          $toggle.removeClass("selected");
        } else {
          $toggle.addClass("selected");
        }

        if (fire) {
          $select.val($opt.val()).trigger("change");
        }
      }

      function position() {
        if (!$wrap.hasClass("open")) return;

        var r = $wrap[0].getBoundingClientRect();
        var vh = window.innerHeight || document.documentElement.clientHeight;
        var below = Math.max(0, vh - r.bottom - 8);
        var above = Math.max(0, r.top - 8);

        var natural = $menu
          .removeClass("drop-up")
          .css({ maxHeight: "" })
          .outerHeight();

        var up = natural > below && above > below;
        if (up) $menu.addClass("drop-up");

        var avail = up ? above : below;
        var maxH = Math.max(120, avail);

        $menu.css({
          maxHeight: maxH,
          overflowY: natural > maxH ? "auto" : "hidden",
        });
      }

      function filterMenu(keyword) {
        var text = $.trim(keyword).toLowerCase();
        var visibleCount = 0;

        $menu.find(".u-item").each(function () {
          var $item = $(this);
          var itemText = $.trim($item.text()).toLowerCase();

          if (!text || itemText.indexOf(text) > -1) {
            $item.show();
            visibleCount++;
          } else {
            $item.hide();
          }
        });

        return visibleCount;
      }

      function resetFilterToSelected() {
        $menu.find(".u-item").show();
        setDisplayText(selectedTextCache);
      }

      function open() {
        if ($select.prop("disabled")) return;

        closeAll();
        $wrap.addClass("open").attr("aria-expanded", "true");

        if (isSearchable) {
          resetFilterToSelected();
        }

        position();

        var $container = $wrap.closest(".search-wrap");
        if ($container.length) $container.addClass("has-open-dropdown");

        if (isSearchable) {
          setTimeout(function () {
            $toggle.trigger("focus");
            $toggle.select();
          }, 0);
        }
      }

      function close(restoreText) {
        $wrap.removeClass("open").attr("aria-expanded", "false");

        if (restoreText !== false && isSearchable) {
          $toggle.val(selectedTextCache);
        }

        $menu.find(".u-item").show();

        var $container = $wrap.closest(".search-wrap");
        if ($container.length) {
          if ($container.find(".u-select.open").length === 0) {
            $container.removeClass("has-open-dropdown");
          }
        }
      }

      $toggle.on("click", function (e) {
        e.preventDefault();
        e.stopPropagation();
        $wrap.hasClass("open") ? close(true) : open();
      });

      if (isSearchable) {
        $toggle.on("focus", function (e) {
          e.stopPropagation();
          if (!$wrap.hasClass("open")) {
            open();
          }
        });

        $toggle.on("input", function () {
          var keyword = $(this).val();
          var count = filterMenu(keyword);

          if (!$wrap.hasClass("open")) {
            open();
          }

          if (count > 0) {
            position();
          }
        });
      }

      $toggle.on("keydown", function (e) {
        var k = e.key;
        var $visibleItems = $menu.find(".u-item:visible:not([aria-disabled='true'])");
        var $current = $visibleItems.filter("[aria-selected='true']").first();
        var idx = $visibleItems.index($current);

        if (k === "Escape") {
          e.preventDefault();
          close(true);
          return;
        }

        if (k === "Enter" || (!isSearchable && k === " ")) {
          e.preventDefault();

          if (!$wrap.hasClass("open")) {
            open();
            return;
          }

          if ($visibleItems.length) {
            var $targetEnter = $visibleItems.eq(idx >= 0 ? idx : 0);
            setByValue($targetEnter.data("value"), true);
          }

          close(true);
          return;
        }

        if (k === "ArrowDown" || k === "ArrowUp") {
          e.preventDefault();

          if (!$wrap.hasClass("open")) {
            open();
            return;
          }

          if (!$visibleItems.length) return;

          if (idx < 0) idx = 0;
          else {
            idx =
              k === "ArrowDown"
                ? Math.min($visibleItems.length - 1, idx + 1)
                : Math.max(0, idx - 1);
          }

          var $target = $visibleItems.eq(idx);
          syncSelectedState($target.data("value"));
          setDisplayText($.trim($target.text()));

          var menuEl = $menu[0];
          var itemEl = $target[0];
          if (menuEl && itemEl) {
            var itemTop = itemEl.offsetTop;
            var itemBottom = itemTop + itemEl.offsetHeight;
            var viewTop = menuEl.scrollTop;
            var viewBottom = viewTop + menuEl.clientHeight;

            if (itemTop < viewTop) menuEl.scrollTop = itemTop;
            else if (itemBottom > viewBottom) menuEl.scrollTop = itemBottom - menuEl.clientHeight;
          }
        }
      });

      $menu.on("click", ".u-item", function (e) {
        e.preventDefault();
        e.stopPropagation();
        if ($(this).attr("aria-disabled") === "true") return;

        setByValue($(this).data("value"), true);
        close(true);
      });

      $(document).on("click", function () {
        if ($wrap.hasClass("open")) {
          close(true);
        }
      });

      $(window).on("resize scroll", position);

      var mo = new MutationObserver(function () {
        render();
        setByValue($select.val(), false);
        $wrap.toggleClass("disabled", $select.prop("disabled"));

        if (isSearchable) {
          $toggle.prop("disabled", $select.prop("disabled"));
        } else {
          $toggle.attr("tabindex", $select.prop("disabled") ? -1 : 0);
        }
      });

      mo.observe($select[0], {
        attributes: true,
        childList: true,
        subtree: true,
      });

      render();
      setByValue($select.val(), false);
      $wrap.toggleClass("disabled", $select.prop("disabled"));

      if (isSearchable) {
        $toggle.prop("disabled", $select.prop("disabled"));
      } else {
        $toggle.attr("tabindex", $select.prop("disabled") ? -1 : 0);
      }

      var inlineWidth = $select[0].style.width;
      if (inlineWidth) {
        $wrap.css("width", inlineWidth);
      }

      $select.css({
        position: "absolute",
        opacity: 0,
        width: 0,
        height: 0,
        pointerEvents: "none",
      });

      $select.after($wrap);
    });
  };
})(jQuery);

사용은 이렇게 하면 돼.

기본형:

<select class="u-select-target">

검색형:

<select class="u-select-target u-select-search">

초기화:

$(".u-select-target").upgradeSelectToDropdown();

그리고 CSS는 검색형 input이 깨지지 않게 이것만 하나 추가해주면 좋아:

.u-select-input {
  width: 100%;
  box-sizing: border-box;
  cursor: text;
}

정리하면:
	•	u-select-search 없음 → 기존 드롭다운처럼 동작
	•	u-select-search 있음 → 같은 u-select 스타일인데 입력/검색 가능

이렇게 하면 기존 화면 안 깨고 필요한 곳만 검색형으로 바꿀 수 있어.



맞아, 이거면 새로 따로 만들기보다 u-select 자체에 검색 기능을 녹이는 게 제일 자연스러워.

지금 구조를 보면 이미:
	•	원본 select 숨김
	•	u-select 커스텀 UI 생성
	•	option 렌더링
	•	선택값 동기화

까지 다 되어 있어서, 여기에 검색 input + 필터링만 얹으면 돼.

핵심 아이디어는 이거야:
	•	기존 u-select-toggle를 div 대신 input으로 바꿈
	•	input에 텍스트 입력하면 u-item 필터링
	•	항목 클릭하면 input에 선택 텍스트 표시
	•	실제 값은 기존처럼 원본 select에 반영
	•	바깥 클릭하면 닫고, 선택 안 했으면 원래 선택값 텍스트로 복원

아래는 네 코드에 맞춰 검색형으로 통합한 버전이야.

// ========== 커스텀 셀렉트 + 검색 ==========
(function ($) {
  function closeAll() {
    $(".u-select.open").each(function () {
      var $wrap = $(this);
      $wrap.removeClass("open").attr("aria-expanded", "false");

      var $container = $wrap.closest(".search-wrap");
      if ($container.length) {
        if ($container.find(".u-select.open").length === 0) {
          $container.removeClass("has-open-dropdown");
        }
      }
    });
  }

  $.fn.upgradeSelectToDropdown = function () {
    return this.each(function () {
      var $select = $(this);
      if ($select.data("upgraded")) return;
      $select.data("upgraded", true);

      var $wrap = $(
        '<div class="u-select" role="combobox" aria-expanded="false" style="margin-top: 5px;">' +
          ' <input type="text" class="u-select-toggle u-select-input" autocomplete="off" />' +
          ' <div class="u-menu" role="listbox"></div>' +
        "</div>"
      );

      var $toggle = $wrap.find(".u-select-toggle");
      var $menu = $wrap.find(".u-menu");
      var selectedTextCache = "";

      function render() {
        $menu.empty();

        $select.find("option").each(function () {
          var dis = this.disabled ? ' aria-disabled="true"' : "";
          $menu.append(
            '<div class="u-item" role="option" data-value="' +
              this.value +
              '" data-text="' +
              $('<div>').text($(this).text()).html() +
              '"' +
              dis +
              ">" +
              $(this).text() +
              "</div>"
          );
        });
      }

      function isPlaceholder($opt) {
        return $opt.is("[data-placeholder]") || $.trim($opt.val()) === "";
      }

      function getSelectedOption() {
        var $opt = $select.find("option:selected");
        if (!$opt.length) $opt = $select.find("option").eq(0);
        return $opt;
      }

      function syncSelectedState(val) {
        $menu.find(".u-item").attr("aria-selected", "false");
        $menu.find('.u-item[data-value="' + val + '"]').attr("aria-selected", "true");
      }

      function setByValue(val, fire) {
        var $opt = $select.find('option[value="' + val + '"]');
        if (!$opt.length) $opt = $select.find("option").eq(0);

        selectedTextCache = $.trim($opt.text());
        $toggle.val(selectedTextCache);
        syncSelectedState($opt.val());

        if (isPlaceholder($opt)) {
          $toggle.removeClass("selected");
        } else {
          $toggle.addClass("selected");
        }

        if (fire) {
          $select.val($opt.val()).trigger("change");
        }
      }

      function position() {
        if (!$wrap.hasClass("open")) return;

        var r = $wrap[0].getBoundingClientRect();
        var vh = window.innerHeight || document.documentElement.clientHeight;
        var below = Math.max(0, vh - r.bottom - 8);
        var above = Math.max(0, r.top - 8);

        var natural = $menu
          .removeClass("drop-up")
          .css({ maxHeight: "" })
          .outerHeight();

        var up = natural > below && above > below;
        if (up) $menu.addClass("drop-up");

        var avail = up ? above : below;
        var maxH = Math.max(120, avail);

        $menu.css({
          maxHeight: maxH,
          overflowY: natural > maxH ? "auto" : "hidden",
        });
      }

      function filterMenu(keyword) {
        var text = $.trim(keyword).toLowerCase();
        var visibleCount = 0;

        $menu.find(".u-item").each(function () {
          var $item = $(this);
          var itemText = $.trim($item.text()).toLowerCase();

          if (!text || itemText.indexOf(text) > -1) {
            $item.show();
            visibleCount++;
          } else {
            $item.hide();
          }
        });

        return visibleCount;
      }

      function resetFilterToSelected() {
        $menu.find(".u-item").show();
        $toggle.val(selectedTextCache);
      }

      function open() {
        if ($select.prop("disabled")) return;

        closeAll();
        $wrap.addClass("open").attr("aria-expanded", "true");

        // 열 때 기존 선택 텍스트를 보여주고, 전체 목록 표시
        resetFilterToSelected();
        position();

        var $container = $wrap.closest(".search-wrap");
        if ($container.length) $container.addClass("has-open-dropdown");

        // 입력칸 포커스 + 전체선택
        setTimeout(function () {
          $toggle.trigger("focus");
          $toggle.select();
        }, 0);
      }

      function close(restoreText) {
        $wrap.removeClass("open").attr("aria-expanded", "false");

        if (restoreText !== false) {
          $toggle.val(selectedTextCache);
        }

        $menu.find(".u-item").show();

        var $container = $wrap.closest(".search-wrap");
        if ($container.length) {
          if ($container.find(".u-select.open").length === 0) {
            $container.removeClass("has-open-dropdown");
          }
        }
      }

      $toggle.on("focus click", function (e) {
        e.stopPropagation();
        if (!$wrap.hasClass("open")) {
          open();
        }
      });

      $toggle.on("input", function () {
        var keyword = $(this).val();
        var count = filterMenu(keyword);

        if (!$wrap.hasClass("open")) {
          open();
        }

        if (count > 0) {
          position();
        }
      });

      $toggle.on("keydown", function (e) {
        var k = e.key;
        var $visibleItems = $menu.find(".u-item:visible:not([aria-disabled='true'])");
        var $current = $visibleItems.filter("[aria-selected='true']").first();
        var idx = $visibleItems.index($current);

        if (k === "Escape") {
          e.preventDefault();
          close(true);
          return;
        }

        if (k === "ArrowDown" || k === "ArrowUp") {
          e.preventDefault();

          if (!$wrap.hasClass("open")) {
            open();
            return;
          }

          if (!$visibleItems.length) return;

          if (idx < 0) idx = 0;
          else {
            idx = k === "ArrowDown"
              ? Math.min($visibleItems.length - 1, idx + 1)
              : Math.max(0, idx - 1);
          }

          var $target = $visibleItems.eq(idx);
          syncSelectedState($target.data("value"));
          $toggle.val($.trim($target.text()));

          var menuEl = $menu[0];
          var itemEl = $target[0];
          if (menuEl && itemEl) {
            var itemTop = itemEl.offsetTop;
            var itemBottom = itemTop + itemEl.offsetHeight;
            var viewTop = menuEl.scrollTop;
            var viewBottom = viewTop + menuEl.clientHeight;

            if (itemTop < viewTop) menuEl.scrollTop = itemTop;
            else if (itemBottom > viewBottom) menuEl.scrollTop = itemBottom - menuEl.clientHeight;
          }
          return;
        }

        if (k === "Enter") {
          e.preventDefault();

          if (!$wrap.hasClass("open")) {
            open();
            return;
          }

          if ($visibleItems.length) {
            var $targetItem = $visibleItems.eq(idx >= 0 ? idx : 0);
            setByValue($targetItem.data("value"), true);
          }

          close(true);
        }
      });

      $menu.on("click", ".u-item", function (e) {
        e.preventDefault();
        e.stopPropagation();
        if ($(this).attr("aria-disabled") === "true") return;

        setByValue($(this).data("value"), true);
        close(true);
      });

      $(document).on("click", function () {
        if ($wrap.hasClass("open")) {
          close(true);
        }
      });

      $(window).on("resize scroll", position);

      var mo = new MutationObserver(function () {
        render();
        setByValue($select.val(), false);
        $wrap.toggleClass("disabled", $select.prop("disabled"));
        $toggle.prop("disabled", $select.prop("disabled"));
      });

      mo.observe($select[0], {
        attributes: true,
        childList: true,
        subtree: true,
      });

      render();
      setByValue($select.val(), false);

      $wrap.toggleClass("disabled", $select.prop("disabled"));
      $toggle.prop("disabled", $select.prop("disabled"));

      var inlineWidth = $select[0].style.width;
      if (inlineWidth) {
        $wrap.css("width", inlineWidth);
      }

      // 원본 select 숨기고 삽입
      $select.css({
        position: "absolute",
        opacity: 0,
        width: 0,
        height: 0,
        pointerEvents: "none",
      });

      $select.after($wrap);
    });
  };
})(jQuery);

그리고 CSS도 input이 들어가니까 u-select-toggle에 input 스타일을 먹게 조금 맞춰줘야 해:

.u-select {
  position: relative;
}

.u-select-toggle.u-select-input {
  width: 100%;
  box-sizing: border-box;
  cursor: text;
}

.u-menu {
  position: absolute;
  left: 0;
  right: 0;
  z-index: 9999;
}

.u-item[aria-disabled="true"] {
  opacity: 0.5;
  pointer-events: none;
}

동작은 이렇게 돼:
	•	평소엔 선택된 값이 input에 보임
	•	클릭하거나 포커스 주면 열림
	•	입력하면 목록이 필터링됨
	•	Enter / 화살표 / 클릭으로 선택 가능
	•	닫히면 최종 선택 텍스트가 input에 남음
	•	실제 submit 값은 원본 select가 가짐

이 방식의 장점은 기존 u-select 구조와 스타일을 최대한 살리면서 검색만 추가한다는 거야.

원하면 내가 다음 답변에서 이 버전을 기준으로 placeholder 유지, 초기값 없을 때 빈칸 처리, 한글 입력 대응 안정화까지 다듬어서 더 줄게.