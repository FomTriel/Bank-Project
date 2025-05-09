import java.util.*;
import java.security.SecureRandom;



public class BankingApplication {

    //list of user accounts
    private static final List<Account> accounts = new ArrayList<>();
    private static Account loggedInUser = null;

    //Main Menu
    public static void main(String[] args) {
        Scanner input = new Scanner(System.in);
        boolean exit = false;
        while (!exit) { //keep looping until exit is selected
            System.out.println("\n--- Banking App ---");
            System.out.println("1. Create Account");
            System.out.println("2. Login");
            System.out.println("3. Check Balance");
            System.out.println("4. Deposit");
            System.out.println("5. Withdraw");
            System.out.println("6. Logout");
            System.out.println("7. Exit");
            System.out.print("Enter choice: ");

            //switch case for input user input
            switch (input.nextLine()) {
                case "1": createAccount(input); break;
                case "2": login(input);         break;
                case "3": checkBalance();       break;
                case "4": deposit(input);       break;
                case "5": withdraw(input);      break;
                case "6": logout();             break;
                case "7": exit = true;          break;
                default:  System.out.println("Invalid choice."); 
            }
        }

        input.close();
        System.out.println("Exiting application");
    }

    //asks for username and password , salts, hashes and stores them in the accounts list
private static void createAccount(Scanner scanner) {
    System.out.print("New username: ");
    String user = scanner.nextLine();

    // Regex: only letters or digits, length 3 to 15
    if (!user.matches("^[A-Za-z0-9]{3,15}$")) {
        System.out.println("Invalid username. Must be 3 to 15 letters or digits.");
        return;
    }

    // Check if username is already taken
    for (Account a : accounts) {
        if (a.getUsername().equals(user)) {
            System.out.println("Username taken."); // checks if username is taken
            return;
        }
    }

    // Set password
    System.out.print("New password: ");
    String pass = scanner.nextLine();

    // Regex for password: 8-20 characters,one uppercase, one lowercase, one digit, and one special character
    if (!pass.matches("^(?=.*[A-Z])(?=.*[a-z])(?=.*\\d)(?=.*[@$!%*?&])[A-Za-z\\d@$!%*?&]{8,20}$")) {
        System.out.println("Invalid password. Must be 8-20 characters long, include at least one uppercase letter, one lowercase letter, one digit, and one special character.");
        return;
    }

    // Generate salt and hash the password
    try {
        byte[] salt = PasswordEncryptionService.generateSalt();
        byte[] hash = PasswordEncryptionService.getEncryptedPassword(pass, salt);
        accounts.add(new Account(user, hash, salt));
        System.out.println("Account created");
    } catch (Exception e) {
        System.err.println("Error creating account: " + e.getMessage());
    }
}

    //simulates sending a one time password to the user (MFA)
    private static String generateOTP() {
        return String.valueOf(100000 + new SecureRandom().nextInt(900000));
    }

    
    // Example prepared statement for inserting into the database:
    /* 
    Connection conn = DbUtil.getConnection();
    String sql = "INSERT INTO accounts (username, password_hash, salt, balance) VALUES (?, ?, ?, 0)";
    PreparedStatement ps = conn.prepareStatement(sql);

    ps.setString(1, user);
    ps.setBytes(2, hash);
    ps.setBytes(3, salt);
    ps.executeUpdate();
    conn.close();
    */

    //login method
    private static void login(Scanner scanner) {
        System.out.print("Username: ");
        String user = scanner.nextLine();
        System.out.print("Password: ");
        String pass = scanner.nextLine();
        

          try {
            for (Account acc : accounts) {
                if (acc.getUsername().equals(user)) {
                    byte[] enc = PasswordEncryptionService
                                  .getEncryptedPassword(pass, acc.getSalt());
                    if (!Arrays.equals(enc, acc.getHashedPassword())) {
                        System.out.println("Invalid password."); return;
                    }

                    // MFA
                    String otp = generateOTP();
                    System.out.println("Your One Time Password: " + otp);
                    System.out.print("Enter OTP: ");
                    if (!otp.equals(scanner.nextLine())) {
                        System.out.println("Incorrect OTP."); return;
                    }
                    loggedInUser = acc;
                    System.out.println("Login successful!");
                    return;
                }
            }
            System.out.println("Invalid username or password.");
        } catch (Exception e) {
            System.err.println("Login error: " + e.getMessage());
        }
    }
    

    //returns balance of the logged in user
    private static void checkBalance() {
        if (!isLoggedIn()) return;
        System.out.printf("Balance: $%.2f%n", loggedInUser.getBalance());
    }


    //deposit method to add money to the account
    private static void deposit(Scanner input) {
        if (!isLoggedIn()) return;
        System.out.print("Amount to deposit: ");
        String in = input.nextLine();

    // Regex for extra security: integer or decimal with up to two places
    if (!in.matches("^\\d+(\\.\\d{1,2})?$")) {
        System.out.println("Invalid format. Enter a number with up to two decimals.");
        return;
    }

        //error handling for invalid input
        try {
            double amt = Double.parseDouble(in);
            if (amt > 0) {
                loggedInUser.setBalance(loggedInUser.getBalance() + amt);
                System.out.println("Deposited $" + amt);
            } else {
                System.out.println("Enter a valid amount greater than 0.");
            }
        } catch (NumberFormatException e) {
            System.out.println("Invalid number. Please enter a numeric value.");
        }
    }

    //withdraw reads amount and checks validity then subtracts
    private static void withdraw(Scanner input) {
        if (!isLoggedIn()) return;
        System.out.print("Amount to withdraw: ");
        String in = input.nextLine();

        // Regex for extra security: integer or decimal with up to two places
        if (!in.matches("^\\d+(\\.\\d{1,2})?$")) {
            System.out.println("Invalid format. Enter a number with up to two decimals.");
            return;
        }

        // Error handling for invalid input
        try {
            double amt = Double.parseDouble(in);
            if (amt <= 0) {
                System.out.println("Enter a valid amount.");
            } else if (amt > loggedInUser.getBalance()) {
                System.out.println("Insufficient funds.");
            } else {
                loggedInUser.setBalance(loggedInUser.getBalance() - amt);
                System.out.println("Withdrew $" + amt);
            }
        } catch (NumberFormatException e) {
            System.out.println("Invalid number. Please enter a numeric value.");
        }
    }

        //returns loggedInUser to null
    private static void logout() {
        if (!isLoggedIn()) return;
        System.out.println("Logging out " + loggedInUser.getUsername());
        loggedInUser = null;
    }

    private static boolean isLoggedIn() {
        if (loggedInUser == null) {
            System.out.println("Please log in first."); return false;
        }
        return true;
    }
}
