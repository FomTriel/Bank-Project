// Account.java

public class Account {
    private final String username;
    private final byte[] hashedPassword;
    private final byte[] salt;
    private double balance;

    public Account(String username, byte[] hashedPassword, byte[] salt)
    {
        this.username = username;
        this.hashedPassword = hashedPassword;
        this.salt = salt;
        this.balance = 0.0;
    }

    public String getUsername()
    { return username;}

    public byte[] getHashedPassword()
    { return hashedPassword;}

    public byte[] getSalt()
    { return salt; }

    public double getBalance()
    { return balance; }

    public void setBalance(double b)
    { balance = b; }
}
