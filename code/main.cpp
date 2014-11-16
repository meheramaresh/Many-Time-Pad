#include <iostream>
#include <stdio.h>
#include <pthread.h>
#include <vector>
#include <fstream>
#include <sstream>
#include <algorithm>
#include <stdexcept>
#include <unistd.h>
#include <pwd.h>
#include <iostream>

using namespace std;

/* Global variables */
vector<string> words;
string *decryptMsg1;
string *decryptMsg2;

/* Function Prototypes */
extern void sort_file(char* fsrc, char* fdest, int count);
void* sorting_thread(void* count);
string decrypt(string resultCipher, string hexGuessedWord, string msg);
string string_to_hex(string input);
string hex_to_string(string input);
int hexCharToInt(char a);
string xorTwoHexStrings(string *str1, string *str2, int position);
vector<string> listOfSimilarWords(string partialWord);
int binary_search(string word);
int similar_word(string substr);
string decrytpSymbols(string cipher, string msg, string symbol);
bool sortFunction(string a, string b);

int main()
{
    vector<string> ciphers;
    string str;
    ofstream foutpad("pad");
    ofstream foutmsg1("msg000");
    ofstream foutmsg2("msg001");

    struct passwd *pw = getpwuid(getuid());
    char *homedir = pw->pw_dir;

    ifstream finwordlist("words", ifstream::binary);
    if(finwordlist.is_open() == false){
        cout << "Unable to open file word" << endl;
        exit;
    }

    ifstream fincipher1("cipher000", ifstream::binary);
    if(fincipher1.is_open() == false){
        cout << "Unable to open file" << endl;
        exit;
    }
    string cipher1((std::istreambuf_iterator<char>(fincipher1)),
                     std::istreambuf_iterator<char>());

    ifstream fincipher2("cipher001", ifstream::binary);
    if(fincipher2.is_open() == false){
        cout << "Unable to open file" << endl;
        exit;
    }
    string cipher2((std::istreambuf_iterator<char>(fincipher2)),
                     std::istreambuf_iterator<char>());

    /* Read all the words */
    while(finwordlist >> str){
        words.push_back(str);
    }

    /* Sort the words */
    sort(words.begin(), words.end(), sortFunction);


    /* Create a vector for special charecters */
    vector<string> symbols;
    symbols.push_back(" ");
    symbols.push_back(",");
    symbols.push_back("!");
    symbols.push_back("\n");

    /* allocate memory for msg string */
    decryptMsg1 = new string[cipher1.length()/2];
    decryptMsg2 = new string[cipher2.length()/2];

    string finalString = "";
    string backUpFinalString;
    string resultCipher = xorTwoHexStrings(&cipher1, &cipher2, 0);

    /* Fill '&' to the message string */
    finalString.append(resultCipher.length()/2,'&');
    backUpFinalString = finalString;

    /* Loop through each word in the word list */
    for(int i = 0; i < words.size(); i++){
        string guessedWord = words.at(i);
        string hexGuessedWord = string_to_hex(guessedWord);

        finalString = decrypt(resultCipher, hexGuessedWord, finalString);

        if(backUpFinalString.compare(finalString) != 0){
            i = -1;
            backUpFinalString = finalString;
        }
    }

    /* Loop through the message for the special charecters */
    backUpFinalString = finalString;
    for(int i = 0; i < symbols.size(); i++){
        string guessedSymbol = symbols.at(i);
        string hexGuessedSymbol = string_to_hex(guessedSymbol);

        finalString = decrytpSymbols(resultCipher, finalString, hexGuessedSymbol);

        if(backUpFinalString.compare(finalString) != 0){
            i = -1;
            backUpFinalString = finalString;
        }

        if(finalString.find('&') == string::npos){
            break;
        }
    }

    string hexFinalString = string_to_hex(finalString);
    string hexFinal2String = xorTwoHexStrings(&resultCipher, &hexFinalString, 0);
    string final2String = hex_to_string(hexFinal2String);

    foutmsg1.write(finalString.c_str(), finalString.size());
    foutmsg2.write(final2String.c_str(), final2String.size());

    /* Get the message pad */
    string pad1, pad2;
    pad1 = xorTwoHexStrings(&hexFinalString, &cipher1, 0);
    pad2 = xorTwoHexStrings(&hexFinal2String, &cipher2, 0);
    if(pad1.compare(pad2) == 0){
        foutpad << hex_to_string(pad1);
    }
    else{
        foutpad << hex_to_string(xorTwoHexStrings(&hexFinalString, &cipher2, 0));
    }

    /* Close all the streams */
    finwordlist.close();
    fincipher1.close();
    fincipher2.close();
    foutpad.close();
    foutmsg1.close();
    foutmsg2.close();
}

/* Function to decrypt messages */
string decrypt(string resultCipher, string hexGuessedWord, string msg){
    int msgChk = 0;

    /* Curb drag through the cipher (eg using "the") */
    for(int j = 0; hexGuessedWord.length() <= (resultCipher.length() - j); j++){
        msgChk = (j%2 == 0)? msgChk : msgChk + 1;

        /* Check only of unknown part of the mesage */
        if(msg.at(msgChk) == '&'){
            string partialWordHex = xorTwoHexStrings(&resultCipher, &hexGuessedWord, j);
            string partialWord = hex_to_string(partialWordHex);

            /* Check if the partial word is readable (eg. if-abc_, abc_de_ else-abc_de, Hel) */
            if((partialWord.compare("odd length") != 0) && (partialWord.compare("not a hex digit") != 0)){
                if((partialWord.find_last_of(" ") == (partialWord.length() - 1))
                        || (partialWord.find_last_of("!") == (partialWord.length() - 1))
                        || (partialWord.find_last_of(",") == (partialWord.length() - 1))
                        || (partialWord.find_last_of("\n") == (partialWord.length() - 1))){
                    string newPartialWord = partialWord.substr(0, partialWord.length() - 1);

                    if(similar_word(newPartialWord) == 1){
                        string retString = (hex_to_string(hexGuessedWord));
                        msg.replace(j/2, retString.length(), retString);

                        goto Exit;
                    }
                }
                else{
                    string newPartialWord;

                    /* Check if "Hal" has any spaces in between */
                    if(partialWord.find_last_of(" ") != string::npos){
                        size_t pos = partialWord.find_last_of(" ");
                        newPartialWord = partialWord.substr(pos + 1, partialWord.length() - (pos+1));
                    }
                    else if(partialWord.find_last_of(",") != string::npos){
                        size_t pos = partialWord.find_last_of(",");
                        newPartialWord = partialWord.substr(pos + 1, partialWord.length() - (pos+1));
                    }
                    else if(partialWord.find_last_of("!") != string::npos){
                        size_t pos = partialWord.find_last_of("!");
                        newPartialWord = partialWord.substr(pos + 1, partialWord.length() - (pos+1));
                    }
                    else if(partialWord.find_last_of("\n") != string::npos){
                        size_t pos = partialWord.find_last_of("\n");
                        newPartialWord = partialWord.substr(pos + 1, partialWord.length() - (pos+1));
                    }
                    else{
                        newPartialWord = partialWord;
                    }

                    /* Try to get words starting with the readable partial word (eg. Hel -> Help) */
                    vector<string> similarWords = listOfSimilarWords(newPartialWord);

                    /* for "....ab bcd" word senario */
                    if((binary_search(newPartialWord)) != -1 && (hexGuessedWord.length() == (resultCipher.length() - j))){
                        string retGuessedString = hex_to_string(hexGuessedWord);
                        msg.replace(j/2, retGuessedString.length(), retGuessedString);

                        goto Exit;
                    }
                    /* for "..ab bcd... or ..abc... word senario" */
                    else if(similarWords.size() >= 1){
                        for(int i = 0; i < similarWords.size(); i++){

                            /* Xor "Help" with cipher to get back "the p" */
                            string tempSimHexString = string_to_hex(similarWords.at(i));
                            string tempHexString = xorTwoHexStrings(&resultCipher, &tempSimHexString, j);
                            string tempString = hex_to_string(tempHexString);
                            string tempGuessedWordString = hex_to_string(hexGuessedWord); //Contains "the"

                            /* If its not a hex string contineue with the next word */
                            if((tempGuessedWordString.compare("odd length") != 0) && (tempGuessedWordString.compare("not a hex digit") != 0)){
                                continue;
                            }

                            /* "the p" is a superset of "the" */
                            if(tempString.find(tempGuessedWordString) != string::npos){
                                /* Append the guess word to the message */

                                /* Split "the p" to "p" */
                                size_t pos = tempString.find_last_of(" ");

                                /* for "..ab bcd.." type */
                                if(pos != string::npos && pos != (tempString.length() -1)){
                                    string substr = tempString.substr(pos + 1, tempString.length() - (pos + 1));
                                    string completeWord = tempString.substr(0, pos);

                                    string retGuessedString = hex_to_string(hexGuessedWord);
                                    msg.replace(j/2, retGuessedString.length(), retGuessedString);

                                    /*  and guess words of "p" */
                                    vector<string> similarSubStringWords = listOfSimilarWords(substr);
                                    for(int k = 0; k < similarSubStringWords.size(); k++ ){
                                        msg = decrypt(resultCipher, string_to_hex(similarSubStringWords.at(k)), msg);
                                    }

                                    goto Exit;
                                }
                                /* for "..abc..." type */
                                else{
                                    if(similar_word(partialWord) == 1){
                                        string retString = (hex_to_string(hexGuessedWord));
                                        string tempSpaceString = " ";
                                        string tempSpaceHexString = string_to_hex(tempSpaceString);
                                        string nxtSpaceHexChar = xorTwoHexStrings(&resultCipher, &tempSpaceHexString, (j + tempSpaceString.length()));
                                        string nxtSpaceChar = hex_to_string(nxtSpaceHexChar);

                                        if(resultCipher.length() == (j + hexGuessedWord.length())){
                                            msg.replace(j/2, retString.length(), retString);

                                            goto Exit;
                                        }
                                        else if((nxtSpaceChar.compare("odd length") != 0) && (nxtSpaceChar.compare("not a hex digit") != 0)){
                                            string retString = (hex_to_string(hexGuessedWord));
                                            msg.replace(j/2, retString.length(), retString);
                                            //msg.replace((j/2) + retString.length(), 1, 1, ' ');

                                            goto Exit;
                                        }
                                    }
                                    continue;
                                }
                            }
                        }
                    }
                    /* for "...abc..." word senario */
                    else if(partialWord.find_first_of(" ") == string::npos){
                        if(similar_word(partialWord) == 1){
                            string retString = (hex_to_string(hexGuessedWord));
                            string tempSpaceString = " ";
                            string tempSpaceHexString = string_to_hex(tempSpaceString);
                            string nxtSpaceHexChar = xorTwoHexStrings(&resultCipher, &tempSpaceHexString, (j + tempSpaceString.length()));
                            string nxtSpaceChar = hex_to_string(nxtSpaceHexChar);

                            /* Check if its the last message */
                            if(resultCipher.length() == (j + hexGuessedWord.length())){
                                msg.replace(j/2, retString.length(), retString);

                                goto Exit;
                            }
                            /* Check if hex is a string */
                            else if((nxtSpaceChar.compare("odd length") != 0) && (nxtSpaceChar.compare("not a hex digit") != 0)){
                                string retString = (hex_to_string(hexGuessedWord));
                                msg.replace(j/2, retString.length(), retString);

                                goto Exit;
                            }
                        }
                    }
                }
            }
        }
        else{
            continue;
        }
    }

Exit:
    return msg;
}

/* Function to decrypt symbols */
string decrytpSymbols(string cipher, string msg, string symbol){
    for(int i = 0; i < msg.length(); i++){
        if(msg.at(i) == '&'){
            string temp = xorTwoHexStrings(&cipher, &symbol, (i*2));
            string tempString = hex_to_string(temp);

            if((tempString.compare("odd length") != 0) && (tempString.compare("not a hex digit") != 0)){
                    msg.replace(i, 1, hex_to_string(symbol));
                    return msg;
            }
        }
    }
}

/* Function to find out all the similar words to 'partialWord' */
vector<string> listOfSimilarWords(string partialWord){
    vector<string> similarWords;
    int check = 0;
    transform(partialWord.begin(), partialWord.end(), partialWord.begin(), ::tolower);

    /* Loop through all the words */
    for(int i = 0; i < words.size(); i++){
        string tempString = words.at(i);
        transform(tempString.begin(), tempString.end(), tempString.begin(), ::tolower);

        /* Check if the word is less than the partial word */
        if(partialWord.size() <= tempString.size()){
            if(partialWord[0] == tempString.at(0)){
                int j;

                /* Loop through each char of the word */
                for(j = 0; j < partialWord.size(); j++){
                    /* Check each char of the word */
                    if(partialWord[j] == tempString.at(j)){
                        /* Check if all letters have matched */
                        if(j == (partialWord.size() - 1)){
                            /* save the word */
                            similarWords.push_back(tempString);
                            check = 1;
                        }
                    }
                }
            }
            else if(check == 1){
                break;
            }
            else{
            }
        }
    }
    return similarWords;

}


/* Function of find a similar word */
int similar_word(string substr){
    for(int i = 0; i < words.size(); i++){
        if(words.at(i).find(substr) != string::npos)
            return 1;
    }

    return 0;
}

/* Reference : http://stackoverflow.com/questions/12671510/xor-on-two-hexadeicmal-values-stored-as-string-in-c */
/* Function to compare charecters */
int hexCharToInt(char a){
    if(a>='0' && a<='9')
        return(a-48);
    else if(a>='A' && a<='Z')
        return(a-55);
    else
        return(a-87);
}

/* Reference : http://stackoverflow.com/questions/12671510/xor-on-two-hexadeicmal-values-stored-as-string-in-c */
string xorTwoHexStrings(string *str1, string *str2, int position){
    stringstream XORString;
    int i, j;

    for(i = position, j = 0 ; j<(*str2).length() && ((*str2).length() <= ((*str1).length() - position)) ; i++, j++){
        XORString << hex << (hexCharToInt((*str1)[i])^hexCharToInt((*str2)[j]));
    }
    return XORString.str();
}

/* Reference : http://stackoverflow.com/questions/3381614/c-convert-string-to-hexadecimal-and-vice-versa */
/* Function to convert string to hex */
string string_to_hex(string input)
{
    char* lut = "0123456789abcdef";
    size_t len = input.length();

    string output;

    output.reserve(2 * len);
    for (size_t i = 0; i < len; ++i)
    {
        const unsigned char c = input[i];
        output.push_back(lut[c >> 4]);
        output.push_back(lut[c & 15]);
    }

    return output;
}

/* Reference : http://stackoverflow.com/questions/3381614/c-convert-string-to-hexadecimal-and-vice-versa */
/* Function to convert hex to string */
string hex_to_string(string input)
{
    char* lut = "0123456789abcdef";
    size_t len = input.length();

    if (len & 1)
        return "odd length";

    string output;
    output.reserve(len / 2);
    for (size_t i = 0; i < len; i += 2)
    {
        char a = input[i];
        const char* p = lower_bound(lut, lut + 16, a);
        if (*p != a)
            return "not a hex digit";

        char b = input[i + 1];
        const char* q = lower_bound(lut, lut + 16, b);
        if (*q != b)
            return "not a hex digit";

        char c = ((p - lut) << 4) | (q - lut);

        /* check if its the required charecter */
        if(!isalpha(c) && c != ' ' && c != ',' && c != '!' && c != '\n')
            return "not a hex digit";

        output.push_back(c);
    }
    return output;
}

/* Function to binary search the 'word' from the word list */
int binary_search(string word){
    int first = 0;
    int last = words.size() - 1;
    int middle = (first + last)/2;

    while(first <= last){
        if(words.at(middle).compare(word) == 0){
            return middle;
        }
        else if(words.at(middle).compare(word) < 0 /*middle < word*/){
            first = middle + 1;
        }
        else{
            last = middle - 1;
        }

        middle = (first + last)/2;
    }

    if(first > last){
        return -1;
    }
}

/* Function used to sort */
bool sortFunction(string a, string b){
    if(a.compare(b) < 0){
        return true;
    }
    else{
        return false;
    }

}
