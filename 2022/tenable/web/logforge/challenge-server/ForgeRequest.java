// 
// Decompiled by Procyon v0.5.36
// 

package tenb.logforge;

public class ForgeRequest
{
    public long created;
    public int number;
    public String treeType;
    public int radius;
    public boolean bark;
    
    public ForgeRequest() {
        this.treeType = "";
        this.bark = true;
    }
}
