#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <random>
#include <algorithm>

struct Password {
    std::string name;
    std::string password;
    std::string category;
    std::string website;
    std::string login;
};

class PasswordManager {
private:
    std::vector<Password> passwords;
    std::string password;
    std::vector<std::string> categories;
    std::string file;
    int counter;
public:
    PasswordManager(std::string file) {
        this->file = file;
        counter = 0;
    }

    std::string getPassword() {
        return password;
    }

    void setPassword(std::string password) {
        this->password = password;
    }

    /**
 * @brief Sprawdza poprawność hasła porównując pierwszą linie pliku z przechowywaną wartością.
 *
 * Ta funkcja odczytuje pierwszą linię pliku, deszyfruje dane i porównuje je ze znaną wartością.
 * Jeśli odszyfrowane dane są zgodne z wartością, funkcja zwraca true, w przeciwnym razie zwraca false.
 *
 * @return true jeśli hasło jest poprawne, false w przeciwnym razie.
 */
    bool checkPassword() {
        std::ifstream in = std::ifstream(file);
        std::string firstLine;
        std::getline(in, firstLine);
        in.close();
        if (decryptData(firstLine) == "1234567890")
            return true;
        else
            return false;
    }

    /**
 * @brief Szyfruje dane przy użyciu algorytmu szyfrowania.
 *
 * Ta funkcja szyfruje dane wejściowe przy użyciu określonego algorytmu szyfrowania.
 * Każdy znak w danych wejściowych jest przesuwany o określoną liczbę miejsc w alfabecie.
 * Przesunięcie jest obliczane na podstawie wartości hasła.
 *
 * @param data Dane wejściowe do zaszyfrowania.
 * @return Zaszyfrowane dane.
 */
    std::string encryptData(const std::string &data) {
        std::string encryptedData = "";
        for (int i = 0; i < data.length(); ++i) {
            char c = data[i];
            int index = c - ' ';
            switch (counter % 5) {
                case 0: {
                    index = (index + password[0]) % 94;
                }
                case 1: {
                    index = (index + password[1]) % 94;
                }
                case 2: {
                    index = (index + password[2]) % 94;
                }
                case 3: {
                    index = (index + password[3]) % 94;
                }
                case 4: {
                    index = (index + password[4]) % 94;
                }
            }
            c = index + ' ';
            encryptedData += c;
            counter++;
        }
        return encryptedData;
    }

    /**
 * @brief Deszyfruje zaszyfrowane dane przy użyciu odpowiedniego algorytmu.
 *
 * Ta funkcja deszyfruje zaszyfrowane dane przy użyciu określonego algorytmu deszyfrowania.
 * Każdy znak w danych zaszyfrowanych jest przesuwany o odwrotną wartość w stosunku do szyfrowania.
 * Przesunięcie jest obliczane na podstawie wartości hasła.
 *
 * @param data Zaszyfrowane dane do odszyfrowania.
 * @return Odszyfrowane dane.
 */
    std::string decryptData(const std::string &data) {
        std::string decryptedData = "";
        for (int i = 0; i < data.length(); ++i) {
            char c = data[i];
            int index = c - ' ';
            switch (counter % 5) {
                case 0: {
                    index = (index + (94 - (password[0] % 94))) % 94;
                }
                case 1: {
                    index = (index + (94 - (password[1] % 94))) % 94;
                }
                case 2: {
                    index = (index + (94 - (password[2] % 94))) % 94;
                }
                case 3: {
                    index = (index + (94 - (password[3] % 94))) % 94;
                }
                case 4: {
                    index = (index + (94 - (password[4] % 94))) % 94;
                }
            }
            c = index + ' ';
            decryptedData += c;
            counter++;
        }
        return decryptedData;
    }

    /**
 * @brief Dzieli ciąg znaków na podciągi na podstawie określonego separatora.
 *
 * Ta funkcja przyjmuje ciąg znaków i dzieli go na podciągi na podstawie separatora ';'.
 * Wynikowe podciągi są przechowywane w wektorze.
 *
 * @param data Ciąg znaków do podziału.
 * @return Wektor przechowujący podciągi.
 */
    std::vector<std::string> splitString(const std::string &data) {
        std::vector<std::string> v = {""};
        int index = 0;
        for (char i: data) {
            if (i != ';')
                v.at(index) += i;
            else {
                index++;
                v.push_back("");
            }
        }
        return v;
    }

    /**
 * @brief Wczytuje dane z pliku i przetwarza je.
 *
 * Ta funkcja otwiera plik, wczytuje dane i przetwarza je. Odczytuje zaszyfrowane hasło
 * i kategorie, a następnie odszyfrowuje je i dzieli na odpowiednie elementy.
 * Następnie przetwarza kolejne linie pliku, odszyfrowuje je, dzieli na pola i tworzy
 * obiekty typu Password. Obiekty te są następnie dodawane do wektora passwords.
 * Po zakończeniu przetwarzania, plik jest zamykany.
 */
    void readFile() {
        std::ifstream in = std::ifstream(file);

        std::string tmpPassword;
        std::string tmpCategories;
        std::getline(in, tmpPassword);
        //password = decryptData(tmpPassword);
        std::getline(in, tmpCategories);
        categories = splitString(decryptData(tmpCategories));
        std::string tmp = "";
        categories.erase(std::remove_if(categories.begin(), categories.end(),
                                        [&tmp](const std::string &val) { return val == tmp; }), categories.end());

        while (!in.eof()) {
            std::string data;
            std::getline(in, data);
            std::string decryptedData = decryptData(data);
            std::vector<std::string> fields = splitString(decryptedData);

            Password password1;
            if (fields.size() >= 3) {
                password1.name = fields.at(0);
                password1.password = fields.at(1);
                password1.category = fields.at(2);
            }
            if (fields.size() >= 4)
                password1.website = fields.at(3);
            if (fields.size() >= 5)
                password1.login = fields.at(4);

            passwords.push_back(password1);
        }
        in.close();
    }

    /**
 * @brief Zapisuje dane do pliku.
 *
 * Ta funkcja zapisuje dane do pliku. Rozpoczyna od resetowania licznika, otwiera plik do zapisu
 * i zapisuje zaszyfrowane hasło jako pierwszą linię. Następnie zapisuje kategorie, odszyfrowując
 * je i dodając odpowiednie separatory. Po kategoriach, zapisuje poszczególne obiekty typu Password,
 * odszyfrowując dane i tworząc odpowiednie linie. Po zakończeniu zapisu, plik jest zamykany.
 */
    void saveFile() {
        counter = 0;
        std::ofstream out = std::ofstream(file);

        out << encryptData("1234567890") << std::endl;
        for (std::string val: categories) {
            std::string data = val + ";";
            out << encryptData(data);
        }

        for (Password val: passwords) {
            std::string data = val.name + ";" + val.password + ";" + val.category + ";" + val.website + ";" + val.login;
            out << "\n";
            out << encryptData(data);
        }
        out.close();
    }

    /**
 * @brief Wyświetla informacje o haśle.
 *
 * Ta funkcja wyświetla informacje o podanym haśle, takie jak nazwa, hasło, kategoria, strona internetowa (jeśli istnieje)
 * i login (jeśli istnieje). Informacje są wyświetlane na standardowym wyjściu.
 *
 * @param val Hasło do wyświetlenia.
 */
    void printPassword(const Password &val) {
        std::cout << "Name: [" << val.name << "], Password: [" << val.password;
        std::cout << "], Category: [" << val.category << "]";
        if (!val.website.empty())
            std::cout << ", Website: [" << val.website << "]";
        if (!val.login.empty())
            std::cout << ", Login: [" << val.login << "]";
        std::cout << std::endl;
    }

    /**
 * @brief Sortuje hasła według podanych kryteriów.
 *
 * Ta funkcja sortuje wektor passwords zawierający obiekty typu Password na podstawie
 * podanych kryteriów sortowania w wektorze sortBy. Wewnętrzna funkcja sortująca porównuje
 * elementy hasła na podstawie kolejnych pól sortowania. Początkowo sprawdza się pierwsze pole
 * sortowania, a jeśli elementy są różne, sortuje na podstawie tego pola. Jeśli elementy są
 * równe, przechodzi do kolejnego pola sortowania, aż do wyczerpania wszystkich pól lub
 * znalezienia różnych elementów. Funkcja wywołuje także funkcję printPassword, która drukuje
 * posortowane hasła na ekranie.
 *
 * @param sortBy Wektor określający kolejność pól sortowania.
 */
    void sortPasswords(const std::vector<std::string> &sortBy) {
        std::sort(passwords.begin(), passwords.end(), [&sortBy](const Password a, const Password b) {
            for (const auto &field: sortBy) {
                if (field == "name") {
                    if (a.name != b.name)
                        return a.name < b.name;
                } else if (field == "category") {
                    if (a.category != b.category)
                        return a.category < b.category;
                } else if (field == "website") {
                    if (a.website != b.website)
                        return a.website < b.website;
                } else if (field == "login") {
                    if (a.login != b.login)
                        return a.login < b.login;
                }

            }
            return false;
        });

        for (const auto &val: passwords)
            printPassword(val);
    }

    /**
 * @brief Generuje losowe hasło o określonej długości.
 *
 * Ta funkcja generuje losowe hasło o zadanej długości, uwzględniając różne opcje
 * konfiguracyjne. Można określić długość hasła oraz czy ma zawierać wielkie litery,
 * małe litery i/lub znaki specjalne. Hasło jest generowane na podstawie zestawu
 * znaków, które są dostępne zależnie od wybranych opcji. Wykorzystuje się generator
 * liczb pseudolosowych i równomiernie rozkładaną dystrybucję dla wyboru znaków.
 *
 * @param length Długość generowanego hasła.
 * @param upperCase Flaga określająca, czy hasło ma zawierać wielkie litery.
 * @param lowerCase Flaga określająca, czy hasło ma zawierać małe litery.
 * @param specialChars Flaga określająca, czy hasło ma zawierać znaki specjalne.
 * @return Wygenerowane losowe hasło.
 */
    std::string generateRandomPassword(int length, bool upperCase, bool lowerCase, bool specialChars) {
        std::string charset = "";
        std::string generatedPassword = "";

        if (upperCase)
            charset += "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        if (lowerCase)
            charset += "abcdefghijklmnopqrstuvwxyz";
        if (specialChars)
            charset += "!@#$%^&*()_+-=[]{}|;':,./<>?";

        std::random_device rd;
        std::mt19937 generator(rd());
        std::uniform_int_distribution<int> distribution(0, charset.length() - 1);

        for (int i = 0; i < length; ++i) {
            generatedPassword += charset[distribution(generator)];
        }
        return generatedPassword;
    }

    /**
 * @brief Dodaje nowe hasło do kolekcji haseł.
 *
 * Ta funkcja umożliwia dodanie nowego hasła do kolekcji haseł. Użytkownik ma opcję
 * wyboru sposobu generowania hasła: ręczne wprowadzenie lub automatyczna generacja.
 * Jeśli użytkownik wybierze automatyczną generację, zostaną wyświetlone odpowiednie
 * pytania dotyczące preferencji dotyczących długości hasła oraz zawartości (duże litery,
 * małe litery, znaki specjalne). Wygenerowane hasło zostanie wyświetlone.
 * Następnie użytkownik zostanie poproszony o wprowadzenie nazwy, hasła, kategorii oraz
 * opcjonalnie strony internetowej i loginu. Przed dodaniem nowego hasła sprawdzane są
 * warunki poprawności wprowadzonego hasła oraz kategorii. Jeśli wprowadzone hasło nie jest
 * poprawne lub kategoria nie istnieje, użytkownik jest informowany i proszony o ponowne wprowadzenie.
 * Po poprawnym wprowadzeniu wszystkich danych, nowe hasło zostaje dodane do kolekcji haseł.
 */
    void addPassword() {
        std::cout << "0. Create your own password\n";
        std::cout << "1. Generate password automatically\n";
        std::cout << "Enter your choice:";
        std::string choose;
        std::getline(std::cin, choose);
        if (choose == "1") {
            std::string length;
            std::string upperCase;
            std::string lowerCase;
            std::string specialChars;
            std::cout << "Enter length of the password (8-16):";
            std::getline(std::cin, length);
            std::cout << "Do you want uppercase in your password (1-true, 0-false):";
            std::getline(std::cin, upperCase);
            std::cout << "Do you want lowercase in your password (1-true, 0-false):";
            std::getline(std::cin, lowerCase);
            std::cout << "Do you want special chars in your password (1-true, 0-false):";
            std::getline(std::cin, specialChars);
            int lengthInt = std::stoi(length);
            int upperCaseInt = std::stoi(length);
            int lowerCaseInt = std::stoi(length);
            int specialCharsInt = std::stoi(length);
            std::cout << "Generated password:"
                      << generateRandomPassword(lengthInt, upperCaseInt, lowerCaseInt,
                                                                specialCharsInt) << std::endl;
        }
        Password newPassword;

        std::string name;
        std::cout << "Enter the name:";
        std::getline(std::cin, name);
        newPassword.name = name;

        std::string newPsswd;
        bool PsswdCorrect = false;
        while (!PsswdCorrect) {
            std::cout << "Enter the password:";
            std::getline(std::cin, newPsswd);
            PsswdCorrect = isPsswdCorrect(newPsswd);
            if (!PsswdCorrect)
                std::cout << "Password is not correct, please try again.\n";
        }
        int strength = checkStrength(newPsswd);

        if(strength <= 1)
            std::cout << "Very weak password." << std::endl;
        else if(strength == 2)
            std::cout << "Weak password." << std::endl;
        else if(strength == 3)
            std::cout << "Medium password." << std::endl;
        else if(strength == 4)
            std::cout << "Strong password." << std::endl;

        newPassword.password = newPsswd;

        std::string newCategory;
        bool CategoryCorrect = false;
        while (!CategoryCorrect) {
            std::cout << "Enter the category:";
            std::getline(std::cin, newCategory);
            CategoryCorrect = isCategoryCorrect(newCategory);
            if (!CategoryCorrect)
                std::cout << "Category not exists, please try again.\n";
        }
        newPassword.category = newCategory;

        std::cout << "Enter the website (optional):";
        std::getline(std::cin, newPassword.website);

        std::cout << "Enter the login (optional):";
        std::getline(std::cin, newPassword.login);

        passwords.push_back(newPassword);
    }

    /**
 * @brief Sprawdza siłę podanego hasła.
 *
 * Ta funkcja ocenia siłę podanego hasła na podstawie jego zawartości.
 * Hasło jest analizowane pod kątem występowania różnych typów znaków,
 * takich jak małe litery, wielkie litery, znaki specjalne i cyfry.
 * Za każdy rodzaj występującego znaku przypisywana jest wartość punktowa.
 * Funkcja zwraca sumę punktów, które określają siłę hasła.
 *
 * @param val Hasło do oceny siły.
 * @return Siła hasła w postaci liczby całkowitej. Im wyższa wartość, tym silniejsze hasło.
 */
    int checkStrength(const std::string &val){
        int strength = 0;
        bool lowerCase = false;
        bool upperCase = false;
        bool specialChars = false;
        bool digits = false;
        for(char i : val){
            if(i>=65 && i<=90)
                lowerCase = true;
            else if(i>=97 && i<=122)
                upperCase = true;
            else if((i>=33 && i<=47) || (i>=58 && i<=64) || (i>=91 && i<=96) || (i>=123 && i<=126))
                specialChars = true;
            else if(i>=48 && i<=57)
                digits = true;
        }

        if(lowerCase && upperCase)
            strength++;
        if(specialChars)
            strength++;
        if(digits)
            strength++;
        if(val.length() >= 10)
            strength++;

        return strength;
    }

/**
 * @brief Usuwa wybrane hasła na podstawie podanych nazw.
 *
 * Ta funkcja umożliwia usunięcie wybranych haseł na podstawie podanych nazw.
 * Użytkownik jest proszony o wprowadzenie nazw haseł do usunięcia, oddzielonych średnikiem (;).
 * Następnie użytkownik jest proszony o potwierdzenie usunięcia haseł.
 * Jeśli potwierdzenie jest "yes", haseł o podanych nazwach zostaną usunięte.
 * W przypadku sukcesu wyświetlany jest komunikat o pomyślnym usunięciu określonej liczby haseł.
 * W przeciwnym razie wyświetlany jest komunikat o braku pasujących haseł.
 *
 * @return Wartość 0, jeśli hasła zostały pomyślnie usunięte, 1 w przeciwnym razie.
 */
    int deletePasswords() {
        std::cout << "Enter the names of the passwords to delete\n"
                     "[e.g. 'first name;second name;third name']:";
        std::string name;
        std::getline(std::cin, name);
        std::cout << "Are you sure you want to delete these passwords?\n"
                     "['yes' or 'no']:";
        std::string confirmation;
        std::getline(std::cin, confirmation);
        if (confirmation != "yes") {
            std::cout << "Confirmation not confirmed.";
            return 1;
        }
        std::vector<std::string> names = splitString(name);

        int count = 0;
        passwords.erase(std::remove_if(passwords.begin(), passwords.end(),
                                       [&names, &count](const Password &val) {
                                           if (std::find(names.begin(), names.end(), val.name) != names.end()) {
                                               count++;
                                               return true;
                                           }
                                           return false;
                                       }), passwords.end());

        if (count > 0)
            std::cout << "Successfully deleted " << count << " passwords.\n";
        else
            std::cout << "No matching passwords found.";
        return 0;
    }

    /**
 * @brief Sprawdza poprawność hasła.
 *
 * Ta funkcja sprawdza, czy podane hasło znajduje się w wektorze passwords. Przechodzi przez
 * każde hasło w wektorze i porównuje je z podanym hasłem. Jeśli odnajdzie pasujące hasło,
 * zwraca false, w przeciwnym razie zwraca true.
 *
 * @param psswd Hasło do sprawdzenia.
 * @return Wartość logiczna określająca poprawność hasła (true - poprawne, false - niepoprawne).
 */
    bool isPsswdCorrect(const std::string &psswd) {
        for (Password val: passwords)
            if (val.password == psswd)
                return false;
        return true;
    }

    /**
 * @brief Sprawdza poprawność kategorii.
 *
 * Ta funkcja sprawdza, czy podana kategoria znajduje się w wektorze categories. Przechodzi przez
 * każdą kategorię w wektorze i porównuje ją z podaną kategorią. Jeśli odnajdzie pasującą kategorię,
 * zwraca true, w przeciwnym razie zwraca false.
 *
 * @param data Kategoria do sprawdzenia.
 * @return Wartość logiczna określająca poprawność kategorii (true - poprawna, false - niepoprawna).
 */
    bool isCategoryCorrect(const std::string &data) {
        for (std::string val: categories)
            if (val == data)
                return true;
        return false;
    }

    /**
 * @brief Dodaje nową kategorię.
 *
 * Ta funkcja dodaje nową kategorię do wektora categories. Sprawdza najpierw, czy podana kategoria
 * już istnieje w wektorze. Jeśli istnieje, wyświetla odpowiedni komunikat i zwraca wartość 1.
 * W przeciwnym razie dodaje nową kategorię do wektora categories i zwraca wartość 0.
 *
 * @param newCategory Nowa kategoria do dodania.
 * @return Wartość określająca wynik operacji (0 - sukces, 1 - kategoria już istnieje).
 */
    int addCategory(const std::string &newCategory) {
        for (std::string val: categories)
            if (val == newCategory) {
                std::cout << "Category not added - already exists.";
                return 1;
            }
        categories.push_back(newCategory);
        return 0;
    }

    /**
 * @brief Usuwa kategorię.
 *
 * Ta funkcja usuwa podaną kategorię z wektora categories oraz usuwa wszystkie hasła związane z tą kategorią
 * z wektora passwords. Wykorzystuje funkcję `std::remove_if` wraz z odpowiednim predykatem dla obu wektorów.
 *
 * @param category Kategoria do usunięcia.
 */
    void deleteCategory(const std::string &category) {
        passwords.erase(std::remove_if(passwords.begin(), passwords.end(), [&category](const Password &val) {
            return val.category == category;
        }), passwords.end());
        categories.erase(std::remove_if(categories.begin(), categories.end(), [&category](const std::string &val) {
            return val == category;
        }), categories.end());
    }

    /**
 * @brief Wyszukuje hasła pasujące do zapytania.
 *
 * Ta funkcja wyszukuje w wektorze passwords hasła, które zawierają podane zapytanie.
 * Wyszukiwanie jest wykonywane w polach name, password, category, website i login.
 * Jeśli któreś pole zawiera zapytanie, hasło jest wyświetlane za pomocą funkcji printPassword().
 *
 * @param query Zapytanie do wyszukania.
 */
    void searchPasswords(const std::string &query) {
        for (const Password &val: passwords)
            if (val.name.find(query) != std::string::npos ||
                val.password.find(query) != std::string::npos ||
                val.category.find(query) != std::string::npos ||
                val.website.find(query) != std::string::npos ||
                val.login.find(query) != std::string::npos)
                printPassword(val);
    }

/**
 * @brief Edytuje istniejące hasło.
 *
 * Ta funkcja umożliwia edycję istniejącego hasła na podstawie podanej nazwy.
 * Użytkownik jest proszony o wprowadzenie nowych wartości dla nazwy, hasła, kategorii, strony internetowej (opcjonalnie) i loginu (opcjonalnie).
 * Po znalezieniu hasła o podanej nazwie, jego wartości są aktualizowane na nowe wartości.
 */
    void editPassword(){
        std::cout << "Enter the name of the password to edit:";
        std::string name;
        std::getline(std::cin, name);
        Password newPassword;
        std::cout << "Enter the new name:";
        std::getline(std::cin, newPassword.name);
        std::cout << "Enter the new password:";
        std::getline(std::cin, newPassword.password);
        std::cout << "Enter the new category:";
        std::getline(std::cin, newPassword.category);
        std::cout << "Enter the new website (optional):";
        std::getline(std::cin, newPassword.website);
        std::cout << "Enter the new login (optional):";
        std::getline(std::cin, newPassword.login);

        for(Password &val : passwords)
            if(val.name == name){
                val = newPassword;
                break;
            }
    }
};

int main() {
    std::string path;
    std::cout << "Enter the source file or path:";
    std::getline(std::cin, path);
    PasswordManager passwordManager(path);

    std::string password;
    std::cout << "Enter password to file:";
    std::getline(std::cin, password);

    if (password.length() != 5) {
        std::cout << "Wrong password." << std::endl;
        return 1;
    }

    passwordManager.setPassword(password);
    if (!passwordManager.checkPassword()) {
        std::cout << "Wrong password." << std::endl;
        return 1;
    }

    std::cout << "Correct password." << std::endl;

    passwordManager.readFile();


    std::string command = "";
    int commandInt = -1;
    while (commandInt != 0) {
        std::cout << "------------------------\n";
        std::cout << "1. Search passwords\n";
        std::cout << "2. Sort passwords\n";
        std::cout << "3. Add password\n";
        std::cout << "4. Edit password\n";
        std::cout << "5. Delete password\n";
        std::cout << "6. Add category\n";
        std::cout << "7. Delete category\n";
        std::cout << "0. Exit\n";
        std::cout << "Enter your choice:";

        std::getline(std::cin, command);
        commandInt = std::stoi(command);

        switch (commandInt) {
            case 1: {
                std::cout << "Enter the string you want to find in any field of password:";
                std::string query;
                std::getline(std::cin, query);
                passwordManager.searchPasswords(query);
                break;
            }
            case 2: {
                std::cout << "Enter fields to sort by (choose from: name, category, website, login)\n";
                std::cout << "[e.g. 'name;website']:";
                std::string fields;
                std::getline(std::cin, fields);
                std::vector<std::string> sortBy = passwordManager.splitString(fields);
                passwordManager.sortPasswords(sortBy);
                break;
            }
            case 3: {
                passwordManager.addPassword();
                break;
            }
            case 4: {
                passwordManager.editPassword();
                break;
            }
            case 5: {
                passwordManager.deletePasswords();
                break;
            }
            case 6: {
                std::cout << "Enter the category to add:";
                std::string category;
                std::getline(std::cin, category);
                passwordManager.addCategory(category);
                break;
            }
            case 7: {
                std::cout << "Enter the category to delete:";
                std::string category;
                std::getline(std::cin, category);
                passwordManager.deleteCategory(category);
                break;
            }
            case 0: {
                passwordManager.saveFile();
                break;
            }
            default: {
                std::cout << "Invalid choice. Try again.\n";
                break;
            }
        }
        std::cout << std::endl;
    }
    return 0;
}
