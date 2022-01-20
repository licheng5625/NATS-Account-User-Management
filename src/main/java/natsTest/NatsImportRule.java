package natsTest;

import java.util.Locale;

public class NatsImportRule {
    public String name = "default";
    public String subject = ">";
    public String account = null;
    public Types type = Types.STREAM;
    public enum Types {
        STREAM{
            @Override
            public String toString() {
                return super.toString().toLowerCase() ;
            }
        },
        SERVICE{
            @Override
            public String toString() {
                return super.toString().toLowerCase(Locale.ROOT) ;
            }
        }
    }

    public NatsImportRule(String account) {
        this.account = account;
    }

    public NatsImportRule(String account, String subject) {
        this(account);
        this.subject = subject;
    }
    public NatsImportRule(String account , String subject, String name ){
        this(account,subject);
        this.name = name;
    }
    public NatsImportRule(String account , String subject, String name, NatsImportRule.Types type){
        this(account,subject, name);
        this.type = type;
    }
}
