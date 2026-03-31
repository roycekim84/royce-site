가능해.
lang 쿠키를 읽으면 돼.

순수 JS

function getCookie(name) {
    var value = "; " + document.cookie;
    var parts = value.split("; " + name + "=");
    if (parts.length === 2) {
        return parts.pop().split(";").shift();
    }
    return null;
}

var lang = getCookie("lang");
console.log(lang);

jQuery 써도 결국 쿠키는 document.cookie

jQuery 자체엔 기본 쿠키 함수가 없어서 보통 위처럼 읽어.

ASP.NET 서버 쪽(C#)에서 가져오려면

var lang = Request.Cookies["lang"]?.Value;

참고

setCookie("lang", "ko") 같은 식으로 저장했다면, 위 코드로 "ko"가 나와.

원하면 내가 setCookie랑 getCookie를 한 세트로 정리해줄게.