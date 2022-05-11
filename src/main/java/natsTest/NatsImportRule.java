package natsTest;

import java.util.Locale;

public class NatsImportRule {
    public String name = "default";
    public String subject = ">";
    public String account = null;
    public String local_subject = null;
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
                return super.toString().toLowerCase() ;
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
    public NatsImportRule(String account, String subject, String local_subject) {
        this(account, subject);
        this.local_subject = local_subject;
    }
    public NatsImportRule(String account , String subject, String local_subject, String name ){
        this(account,subject,local_subject);
        this.name = name;
    }
    public NatsImportRule(String account , String subject, String local_subject, String name, NatsImportRule.Types type){
        this(account,subject,local_subject,name);
        this.type = type;
    }
}
