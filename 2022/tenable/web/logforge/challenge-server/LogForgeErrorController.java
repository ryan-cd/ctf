// 
// Decompiled by Procyon v0.5.36
// 

package tenb.logforge;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.ui.Model;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpServletRequest;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.stereotype.Controller;
import org.springframework.boot.web.servlet.error.ErrorController;

@Controller
public class LogForgeErrorController implements ErrorController
{
    @GetMapping({ "/errpg" })
    public String handleError(@RequestParam(name = "dbgmsg", required = false) final String dbgmsg, final HttpServletRequest request, final HttpServletResponse httpResponse, final Model model) {
        final Object status = request.getAttribute("javax.servlet.error.status_code");
        model.addAttribute("code", status);
        model.addAttribute("msg", (Object)dbgmsg);
        return "errpage";
    }
}
