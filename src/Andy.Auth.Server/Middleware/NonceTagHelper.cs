using Andy.Auth.Server.Configuration;
using Microsoft.AspNetCore.Mvc.Rendering;
using Microsoft.AspNetCore.Mvc.ViewFeatures;
using Microsoft.AspNetCore.Razor.TagHelpers;

namespace Andy.Auth.Server.Middleware;

/// <summary>
/// Stamps the per-request CSP nonce (see <see cref="CspNonce"/>) onto every
/// inline <c>&lt;script&gt;</c> and <c>&lt;style&gt;</c> element so they satisfy
/// the nonce-based Content-Security-Policy shipped in Production/UAT (issue #128).
/// Registered via the wildcard <c>@@addTagHelper</c> in <c>_ViewImports.cshtml</c>,
/// so it applies to all such tags automatically; a tag that already carries an
/// explicit <c>nonce</c> attribute, or a request where CSP is disabled (no nonce
/// in <see cref="Microsoft.AspNetCore.Http.HttpContext.Items"/>), is left untouched.
/// </summary>
[HtmlTargetElement("script")]
[HtmlTargetElement("style")]
public sealed class NonceTagHelper : TagHelper
{
    [HtmlAttributeNotBound]
    [ViewContext]
    public ViewContext ViewContext { get; set; } = default!;

    // Run before the framework's Script/Style tag helpers.
    public override int Order => -1000;

    public override void Process(TagHelperContext context, TagHelperOutput output)
    {
        if (output.Attributes.ContainsName("nonce"))
        {
            return;
        }

        var nonce = CspNonce.Get(ViewContext.HttpContext);
        if (!string.IsNullOrEmpty(nonce))
        {
            output.Attributes.SetAttribute("nonce", nonce);
        }
    }
}
