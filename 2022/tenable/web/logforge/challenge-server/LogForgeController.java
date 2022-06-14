// 
// Decompiled by Procyon v0.5.36
// 

package tenb.logforge;

import org.apache.logging.log4j.LogManager;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestMapping;
import java.time.Instant;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.GetMapping;
import javax.servlet.http.HttpServletRequest;
import java.util.ArrayList;
import org.apache.logging.log4j.Logger;
import org.springframework.stereotype.Controller;

@Controller
public class LogForgeController
{
    private static final Logger logger;
    public ArrayList<ForgeRequest> orders;
    public ForgeRequest newOrder;
    
    public LogForgeController() {
        this.orders = new ArrayList<ForgeRequest>();
        this.newOrder = new ForgeRequest();
    }
    
    @GetMapping({ "/dashboard" })
    public String dashboard(final HttpServletRequest request) {
        return "dashboard";
    }
    
    @RequestMapping(value = { "/dashboard" }, method = { RequestMethod.POST })
    public String dashpost(@RequestParam(name = "treeType", required = false, defaultValue = "Pine") final String treeType, @RequestParam(name = "number", required = false, defaultValue = "1") final int number, @RequestParam(name = "radius", required = false, defaultValue = "1") final int radius, @RequestParam(name = "bark", required = false) final String bark, final HttpServletRequest request) {
        final ForgeRequest newOrder = new ForgeRequest();
        newOrder.number = number;
        newOrder.treeType = treeType;
        newOrder.created = Instant.now().getEpochSecond();
        newOrder.radius = radius;
        if (bark != null) {
            newOrder.bark = true;
        }
        else {
            newOrder.bark = false;
        }
        final ArrayList<ForgeRequest> sessOrders = (ArrayList<ForgeRequest>)request.getSession().getAttribute("orders");
        if (sessOrders == null) {
            this.orders.add(newOrder);
            request.getSession().setAttribute("orders", (Object)this.orders);
        }
        else if (sessOrders.size() < 10) {
            (this.orders = sessOrders).add(newOrder);
            request.getSession().setAttribute("orders", (Object)this.orders);
        }
        return "dashboard";
    }
    
    @RequestMapping(value = { "/dashboard/del" }, method = { RequestMethod.POST })
    public String dashdel(@RequestParam(name = "orderId", required = true) final int orderId, @RequestParam(name = "comment", required = false, defaultValue = "no reason given.") final String comment, final HttpServletRequest request) {
        final ArrayList<ForgeRequest> sessOrders = (ArrayList<ForgeRequest>)request.getSession().getAttribute("orders");
        if (orderId >= 0) {
            sessOrders.remove(orderId);
        }
        request.getSession().setAttribute("orders", (Object)sessOrders);
        LogForgeController.logger.info("Removing OrderId " + orderId + ", " + comment);
        return "redirect:/dashboard";
    }
    
    @GetMapping({ "/login" })
    public String login() {
        return "login";
    }
    
    static {
        logger = LogManager.getLogger("logforge");
    }
}
