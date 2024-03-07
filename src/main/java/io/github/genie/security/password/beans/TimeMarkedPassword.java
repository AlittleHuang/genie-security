package io.github.genie.security.password.beans;

public class TimeMarkedPassword {

    private final String password;
    private final long createTime;

    public TimeMarkedPassword(String password) {
        this(password, System.currentTimeMillis());
    }

    public TimeMarkedPassword(String password, long createTime) {
        this.password = password;
        this.createTime = createTime;
    }

    public long getCreateTime() {
        return this.createTime;
    }

    public String getPassword() {
        return this.password;
    }

}
