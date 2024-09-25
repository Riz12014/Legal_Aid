CREATE DATABASE legal_aid;
USE legal_aid;

CREATE TABLE User (
    ID INT AUTO_INCREMENT PRIMARY KEY,
    UserType ENUM('lawyer', 'customer') NOT NULL,
    FullName VARCHAR(255) NOT NULL,
    DateofBirth DATE NOT NULL,
    ContactNo VARCHAR(15) NOT NULL,
    Password VARCHAR(255) NOT NULL,
    Gender ENUM('Male', 'Female', 'Other') NOT NULL,
    NationalID VARCHAR(50) NOT NULL,
    AddressHouse VARCHAR(255),
    AddressStreet VARCHAR(255),
    AddressArea VARCHAR(255),
    AddressCity VARCHAR(255),
    Email VARCHAR(255) NOT NULL UNIQUE,
    BarNumber VARCHAR(50), -- Only for lawyers
    SpecializedFeilds VARCHAR(255), -- Only for lawyers
    OfficeAddress VARCHAR(255), -- Only for lawyers
    ConsultationFee DECIMAL(10, 2) -- Only for lawyers
);

ALTER TABLE User ADD COLUMN TwoFactorEnabled BOOLEAN DEFAULT FALSE;

CREATE TABLE ConsultationRequests (
    ID INT AUTO_INCREMENT PRIMARY KEY,
    CustomerID INT,
    LawyerID INT,
    Status ENUM('Pending', 'Accepted', 'Rejected') DEFAULT 'Pending',
    RequestDate TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (CustomerID) REFERENCES User(ID),
    FOREIGN KEY (LawyerID) REFERENCES User(ID)
);

CREATE TABLE Consultations (
    ID INT AUTO_INCREMENT PRIMARY KEY,
    LawyerID INT,
    CustomerID INT,
    Date DATETIME NOT NULL,
    Status ENUM('Scheduled', 'Completed', 'Cancelled') DEFAULT 'Scheduled',
    FOREIGN KEY (LawyerID) REFERENCES User(ID),
    FOREIGN KEY (CustomerID) REFERENCES User(ID)
);

CREATE TABLE FavoriteLawyers (
    ID INT AUTO_INCREMENT PRIMARY KEY,
    CustomerID INT,
    LawyerID INT,
    FOREIGN KEY (CustomerID) REFERENCES User(ID),
    FOREIGN KEY (LawyerID) REFERENCES User(ID)
);
CREATE TABLE Payments (
    PaymentID INT AUTO_INCREMENT PRIMARY KEY,
    CustomerID INT,
    LawyerID INT,
    Amount DECIMAL(10, 2) NOT NULL,
    PaymentDate TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    Method ENUM('bKash', 'Nagad') NOT NULL,
    FOREIGN KEY (CustomerID) REFERENCES User(ID),
    FOREIGN KEY (LawyerID) REFERENCES User(ID)
);
CREATE TABLE Admin (
    ID INT AUTO_INCREMENT PRIMARY KEY,
    Name VARCHAR(255) NOT NULL,
    Contact_no VARCHAR(15) NOT NULL,
    Email VARCHAR(255) NOT NULL UNIQUE,
    Password VARCHAR(255) NOT NULL
);
INSERT INTO admin (ID, Name, Contact_no, Email, Password) VALUES ('1', 'Anindita Dash', '01975414473', 'anindita.dk2014@gmail.com', 'abcd1234'), ('2', 'Anisha Irin Ahmed', '01960115664', 'anishairinahmed@gmail.com', '1234abcd');
INSERT INTO admin (ID, Name, Contact_no, Email, Password) VALUES ('3', 'Rizwanul Islam', '01784236618', 'rizwanulislam12014@gmail.com', '12345678');

CREATE TABLE Post_Cases(
    ID INT AUTO_INCREMENT PRIMARY KEY,
    Title_of_Case_Listing VARCHAR(255) NOT NULL,
    Brief_Description VARCHAR(1000) NOT NULL,
    Pick_a_Category VARCHAR(255) NOT NULL,
    Sub_Category VARCHAR(255) NOT NULL,
    City VARCHAR(50) NOT NULL,
    Full_Description VARCHAR(2000) NOT NULL
);
ALTER TABLE Post_Cases
ADD COLUMN Name VARCHAR(255) NOT NULL,
ADD COLUMN Email VARCHAR(255) NOT NULL;

CREATE TABLE Laws (
    id INT AUTO_INCREMENT PRIMARY KEY,
    Crime VARCHAR(255) NOT NULL,
    Law VARCHAR(500) NOT NULL
);

CREATE TABLE Laws (
    id INT AUTO_INCREMENT PRIMARY KEY,
    Crime VARCHAR(255) NOT NULL,
    Law VARCHAR(500) NOT NULL
);
INSERT INTO `laws` (`id`, `Crime`, `Law`) VALUES ('1', 'Murder', 'Whoever commits murder shall be punished with death, or 2[imprisonment] for life, and shall also be liable to fine.'), ('2', 'Child Labour', 'the punishment for employing a child or adolescent in contravention of the law is only a nominal fine up to 5,000 taka.'), ('3', 'Kidnapping', 'Whoever kidnaps any person from Bangladesh or from lawful guardianship, shall be punished with imprisonment of either description for a term which may extend to seven years, and shall also be liable to fine.'), ('4', 'Robbery', 'Whoever commits robbery shall be punished with rigorous imprisonment for a term which may extend to ten years, and shall also be liable to fine; and, if the robbery be committed on the highway between sunset and sunrise, the imprisonment may be extended to fourteen years.'), ('5', 'Theft', 'Whoever commits theft shall be punished with imprisonment of either description for a term which may extend to three years, or with fine, or with both.'), ('6', 'Defamation', 'Whoever defames another shall be punished with simple imprisonment for a term which may extend to two years, or with fine, or with both.'), ('7', 'Domestic Violence', 'A perpetrator shall be punishable with imprisonment which may extend to 6(six) months, or with fine which may extend to 10(ten) thousand Taka.'), ('8', 'Fraud', 'Whoever use any false trade mark or any false property mark shall, unless he proves that he acted without intent to defraud, be punished with imprisonment of either description for a term which may extend to one year, or with fine, or with both.'), ('9', 'Human Trafficking', 'Perpetrators may receive penalties of five years to life imprisonment and a fine of not less than 50,000 Bangladeshi Taka (BDT). '), ('10', 'Bribery', 'The maximum punishment for bribery is seven years imprisonment and a fine.'), ('11', 'Money Laundering', 'Any person who commits or abets or conspires to commit the offence of money laundering, shall be punished with imprisonment for a term of at least 4 years but not exceeding 12 years and, in addition to that, a fine equivalent to the twice of the value of the property involved in the offence.');

CREATE TABLE Lawyer_Rating (
    ID INT AUTO_INCREMENT PRIMARY KEY,
    LawyerID INT,
    CustomerID INT,
    Rating INT NOT NULL,
    Review VARCHAR(255),
    FOREIGN KEY (LawyerID) REFERENCES User(ID),
    FOREIGN KEY (CustomerID) REFERENCES User(ID)
);

CREATE TABLE TwoFactorAuth (
    TOTP_Code VARCHAR(100) NOT NULL,
    Secret VARCHAR(100) NOT NULL,
    UserID INT NOT NULL,
    FOREIGN KEY (UserID) REFERENCES User(ID)
);
