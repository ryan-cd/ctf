# Reverse Me 1
**Category: Android Reverse Engineering**

Here's the app when you run it:

<img width=30% src=images/app.png></img>

A simple password check.

I decompiled the APK and took a look at the source. 

`strings.xml` is a likely place to look for hidden information. Looking there, I found they put a bait flag: `<string name="flag">ENSIBS{non ce n\'est pas le flag :P}</string>`

We need to instead look into the Java source. This is the code that runs when you click the button:

```java
// MainActivity.java
public void onClick(View v) {
    if (NotFlag.getFlag(MainActivity.this.input.getText().toString())) {
        Toast.makeText(MainActivity.this, "Félicitaions, vous pouvez valider avec ce flag", 1).show();
    } else {
        Toast.makeText(MainActivity.this, "Dommage, ce n'est pas le flag", 1).show();
    }
}
```
```java            
// NotFlag.java  
public class NotFlag {
    public static boolean getFlag(String in) {
        if (in.equals("ENSIBS{" + "boussole" + "_" + "is_good_for_the" + "_" + "interiut" + "_" + "ctf" + "}")) {
            return true;
        }
        return false;
    }
}

```

And we can see the flag in `NotFlag.java`.
