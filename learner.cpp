#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <map>
#include <math.h>
#include <cstring>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>

using namespace std;

/** Constants */
char* INPUT_FILE = "KDD+Train.txt";   // Name of input file.
char* TEST_FILE = "KDD+Test.txt";
char* INPUT_FILE_2 = "KDD10PercentTrain.txt";
char* TEST_FILE_2 = "KDD10Test.txt";
char* OUTPUT_FILE = "TestResults.txt";

int SIZE_OF_10_PERCENT_FILE = 494020;   // File Lengths.
int SIZE_OF_FULL_FILE = 4898432;

int* globalRulesResults; // Array to store the results of Warezmaster/client signature detection.

double DURATION_MAX = 58329;            // Interval length (from 0 to variable).
double WRONG_FRAGMENT_MAX = 3;          // Listed in order they appear in data set.
double URGENT_MAX = 14;
double HOT_MAX = 101;
double NUM_FAILED_LOGINS_MAX = 5;
double NUM_COMPROMISED_MAX = 9;
double SU_ATTEMPTED_MAX = 2;
double NUM_ROOT_MAX = 7468;
double NUM_FILE_CREATIONS_MAX = 100;
double NUM_SHELLS_MAX = 5;
double NUM_ACCESS_FILES_MAX = 9;
double COUNT_MAX = 511;
double SRV_COUNT_MAX = 511;
double DST_HOST_COUNT_MAX = 255;
double DST_HOST_SRV_COUNT_MAX = 255;

double AMOUNT_OF_FLAGS = 11;            // Amount of different strings of that field.
double AMOUNT_OF_LABELS = 5;
double AMOUNT_OF_PROTOCOLS = 3;
double AMOUNT_OF_SERVICES = 70;

static map<string, double> flagMap;     // Used to map strings to numbers.
static map<string, double> labelMap;
static map<string, double> protocolMap;
static map<string, double> serviceMap;

/** Structures */
/*
 * colon_separated_only: ctype<char>
 * Not sure what it does (found online), but it allows me to input the data.
 */
struct colon_separated_only: ctype<char>
{
    colon_separated_only(): ctype<char>(get_table()) {}

    static ctype_base::mask const* get_table()
    {
        typedef ctype<char> cctype;
        static const cctype::mask *const_rc= cctype::classic_table();

        static cctype::mask rc[cctype::table_size];
        memcpy(rc, const_rc, cctype::table_size * sizeof(cctype::mask));

        rc[','] = ctype_base::space;
        return &rc[0];
    }
};

/*
 * networkTraffic
 * Structure for the networkTraffic data and has 42 variables.
 */
struct networkTraffic
{
    double duration;
    double protocol_type;
    double service;
    double flag;
    double src_bytes;
    double dst_bytes;
    double land;
    double wrong_fragment;
    double urgent;
    double hot;
    double num_failed_logins;
    double logged_in;
    double num_compromised;
    double root_shell;
    double su_attempted;
    double num_root;
    double num_file_creations;
    double num_shells;
    double num_access_files;
    double num_outbound_cmds;
    double is_host_login;
    double is_guest_login;
    double count;
    double srv_count;
    double serror_rate;
    double srv_serror_rate;
    double rerror_rate;
    double srv_rerror_rate;
    double same_srv_rate;
    double diff_srv_rate;
    double srv_diff_host_rate;
    double dst_host_count;
    double dst_host_srv_count;
    double dst_host_same_srv_rate;
    double dst_host_diff_srv_rate;
    double dst_host_same_src_port_rate;
    double dst_host_srv_diff_host_rate;
    double dst_host_serror_rate;
    double dst_host_srv_serror_rate;
    double dst_host_rerror_rate;
    double dst_host_srv_rerror_rate;
    double label; // Labeled data, does NOT have a value for unlabeled data set.
};

/** Function Prototypes */
int preProcessFlag(string flag);
int preProcessLabel(string label);
int preProcessProtocol(string protocol);
int preProcessService(string service);

void knn(vector<networkTraffic> t, vector<networkTraffic> testData, double k);
void printAllData(vector<networkTraffic> data);
void rules(vector<networkTraffic> t);

vector<networkTraffic> getRandomData(int amount, vector<networkTraffic> t);
vector<networkTraffic> inputData();

/** Functions */
/*
 * int preProcessFlag(string flag)
 * Maps the flags to ints and returns the associated int for a flag.
 */
int preProcessFlag(string flag)
{
    if(flagMap.size() == 0) // If the map has not been created.
    {
        flagMap["SF"] = 0;
        flagMap["S2"] = 1;
        flagMap["S1"] = 2;
        flagMap["S3"] = 3;
        flagMap["OTH"] = 4;
        flagMap["REJ"] = 5;
        flagMap["RSTO"] = 6;
        flagMap["S0"] = 7;
        flagMap["RSTR"] = 8;
        flagMap["RSTOS0"] = 9;
        flagMap["SH"] = 10;
    }
    return flagMap[flag];
}

/*
 * int preProcessLabel(string label)
 * Maps the labels to ints and returns the associated int for a label.
 */
int preProcessLabel(string label)
{
    if(labelMap.size() == 0) // If the map has not been created.
    {
        labelMap["normal"] = 0;
        labelMap["probing"] = 1;
        labelMap["DoS"] = 2;
        labelMap["U2R"] = 3;
        labelMap["R2L"] = 4;
    }
    return labelMap[label];
}

/*
 * int preProcessProtocol(string protocol)
 * Maps the protocols to ints and returns the associated int for a protocol.
 */
int preProcessProtocol(string protocol)
{
    if(protocolMap.size() == 0) // If the map has not been created.
    {
        protocolMap["tcp"] = 0;
        protocolMap["udp"] = 1;
        protocolMap["icmp"] = 2;
    }
    return protocolMap[protocol];
}

/*
 * int preProcessService(string service)
 * Maps the services to ints and returns the associated int for a service.
 */
int preProcessService(string service)
{
    if(serviceMap.size() == 0) // If the map has not been created.
    {
        serviceMap["http"] = 0;
        serviceMap["smtp"] = 1;
        serviceMap["domain_u"] = 2;
        serviceMap["auth"] = 3;
        serviceMap["finger"] = 4;
        serviceMap["telnet"] = 5;
        serviceMap["eco_i"] = 6;
        serviceMap["ftp"] = 7;
        serviceMap["ntp_u"] = 8;
        serviceMap["ecr_i"] = 9;
        serviceMap["other"] = 10;
        serviceMap["urp_i"] = 11;
        serviceMap["private"] = 12;
        serviceMap["pop_3"] = 13;
        serviceMap["ftp_data"] = 14;
        serviceMap["netstat"] = 15;
        serviceMap["daytime"] = 16;
        serviceMap["ssh"] = 17;
        serviceMap["echo"] = 18;
        serviceMap["time"] = 19;
        serviceMap["name"] = 20;
        serviceMap["whois"] = 21;
        serviceMap["domain"] = 22;
        serviceMap["mtp"] = 23;
        serviceMap["gopher"] = 24;
        serviceMap["remote_job"] = 25;
        serviceMap["rje"] = 26;
        serviceMap["ctf"] = 27;
        serviceMap["supdup"] = 28;
        serviceMap["link"] = 29;
        serviceMap["systat"] = 30;
        serviceMap["discard"] = 31;
        serviceMap["X11"] = 32;
        serviceMap["shell"] = 33;
        serviceMap["login"] = 34;
        serviceMap["imap4"] = 35;
        serviceMap["nntp"] = 36;
        serviceMap["uucp"] = 37;
        serviceMap["pm_dump"] = 38;
        serviceMap["IRC"] = 39;
        serviceMap["Z39_50"] = 40;
        serviceMap["netbios_dgm"] = 41;
        serviceMap["ldap"] = 42;
        serviceMap["sunrpc"] = 43;
        serviceMap["courier"] = 44;
        serviceMap["exec"] = 45;
        serviceMap["bgp"] = 46;
        serviceMap["csnet_ns"] = 47;
        serviceMap["http_443"] = 48;
        serviceMap["klogin"] = 49;
        serviceMap["printer"] = 50;
        serviceMap["netbios_ssn"] = 51;
        serviceMap["pop_2"] = 52;
        serviceMap["nnsp"] = 53;
        serviceMap["efs"] = 54;
        serviceMap["hostnames"] = 55;
        serviceMap["uucp_path"] = 56;
        serviceMap["sql_net"] = 57;
        serviceMap["vmnet"] = 58;
        serviceMap["iso_tsap"] = 59;
        serviceMap["netbios_ns"] = 60;
        serviceMap["kshell"] = 61;
        serviceMap["urh_i"] = 62;
        serviceMap["http_2784"] = 63;
        serviceMap["harvest"] = 64;
        serviceMap["aol"] = 65;
        serviceMap["tftp_u"] = 66;
        serviceMap["http_8001"] = 67;
        serviceMap["tim_i"] = 68;
        serviceMap["red_i"] = 69;
    }
    return serviceMap[service];
}

/*
 * void knn(vector<networkTraffic> t, vector<networkTraffic> testData, double k)
 * Runs the K-nearest neighbor (k being the # of neighbors) algorithm on testData.
 * t is the original vector to find the neighbors in.
 */
void knn(vector<networkTraffic> t, vector<networkTraffic> testData, double k)
{
    int tSize = t.size();   // Size of the known values matrix.
    int testSize = testData.size(); // Size of the unknown values matrix.

    int confusionMatrixSize = 5;    // Amount of different attack labels.
    double confusionMatrix[confusionMatrixSize][confusionMatrixSize]; // Confusion matrix for KNN results.
    double confusionMatrix2[confusionMatrixSize][confusionMatrixSize]; // Confusion matrix for KNN results with Warez signatures used.

    // Zero out array.
    for(int a = 0; a < confusionMatrixSize; a++)
    {
        for(int b = 0; b < confusionMatrixSize; b++)
        {
            confusionMatrix[a][b] = 0;
            confusionMatrix2[a][b] = 0;
        }
    }

    // Distances and labels from each point in t to the point being tested.
    double* distance = (double*) malloc(tSize * sizeof(double));
    double* label = (double*) malloc(tSize * sizeof(double));

    // K-nearest distances and associated labels to the point being tested.
    double* knnMinDistances = (double*) malloc(k * sizeof(double));
    double* knnLabels = (double*) malloc(k * sizeof(double));

    // Amount of guesses of each label (the max will be the final guess).
    double* knnGuesses = (double*) malloc(k * sizeof(double));

    // Clear out the memory of all the arrays - just in case.
    memset(distance, 0, tSize);
    memset(label, 0, tSize);
    memset(knnMinDistances, 0, k);
    memset(knnLabels, 0, k);
    memset(knnGuesses, 0, k);

    // K nearest neighbors loop.
    for(int j = 0; j < testSize; j++)
    {
        // Calculate the distances between each point in t and the point j being tested.
        for(int i = 0; i < tSize; i++)
        {
            double sum = pow((t[i].duration - testData[j].duration), 2) +
                         pow((t[i].protocol_type - testData[j].protocol_type), 2) +
                         pow((t[i].service - testData[j].service), 2) +
                         pow((t[i].flag - testData[j].flag), 2) +
                         pow((t[i].src_bytes - testData[j].src_bytes), 2) + // 5
                         pow((t[i].dst_bytes - testData[j].dst_bytes), 2) +
                         pow((t[i].land - testData[j].land), 2) +
                         pow((t[i].wrong_fragment - testData[j].wrong_fragment), 2) +
                         pow((t[i].urgent - testData[j].urgent), 2) +
                         pow((t[i].hot - testData[j].hot), 2) +    // 10
                         pow((t[i].num_failed_logins - testData[j].num_failed_logins), 2) +
                         pow((t[i].logged_in - testData[j].logged_in), 2) +
                         pow((t[i].num_compromised - testData[j].num_compromised), 2) +
                         pow((t[i].root_shell - testData[j].root_shell), 2) +
                         pow((t[i].su_attempted - testData[j].su_attempted), 2) + // 15
                         pow((t[i].num_root - testData[j].num_root), 2) +
                         pow((t[i].num_file_creations - testData[j].num_file_creations), 2) +
                         pow((t[i].num_shells - testData[j].num_shells), 2) +
                         pow((t[i].num_access_files - testData[j].num_access_files), 2) +
                         pow((t[i].num_outbound_cmds - testData[j].num_outbound_cmds), 2) + // 20
                         pow((t[i].is_host_login - testData[j].is_host_login), 2) +
                         pow((t[i].is_guest_login - testData[j].is_guest_login), 2) +
                         pow((t[i].count - testData[j].count), 2) +
                         pow((t[i].srv_count - testData[j].srv_count), 2) +
                         pow((t[i].serror_rate - testData[j].serror_rate), 2) + // 25
                         pow((t[i].srv_serror_rate - testData[j].srv_serror_rate), 2) +
                         pow((t[i].rerror_rate - testData[j].rerror_rate), 2) +
                         pow((t[i].srv_rerror_rate - testData[j].srv_rerror_rate), 2) +
                         pow((t[i].same_srv_rate - testData[j].same_srv_rate), 2) +
                         pow((t[i].diff_srv_rate - testData[j].diff_srv_rate), 2) + // 30
                         pow((t[i].srv_diff_host_rate - testData[j].srv_diff_host_rate), 2) +
                         pow((t[i].dst_host_count - testData[j].dst_host_count), 2) +
                         pow((t[i].dst_host_srv_count - testData[j].dst_host_srv_count), 2) +
                         pow((t[i].dst_host_same_srv_rate - testData[j].dst_host_same_srv_rate), 2) +
                         pow((t[i].dst_host_diff_srv_rate - testData[j].dst_host_diff_srv_rate), 2) + // 35
                         pow((t[i].dst_host_same_src_port_rate - testData[j].dst_host_same_src_port_rate), 2) +
                         pow((t[i].dst_host_srv_diff_host_rate - testData[j].dst_host_srv_diff_host_rate), 2) +
                         pow((t[i].dst_host_serror_rate - testData[j].dst_host_serror_rate), 2) +
                         pow((t[i].dst_host_srv_serror_rate - testData[j].dst_host_srv_serror_rate), 2) +
                         pow((t[i].dst_host_rerror_rate - testData[j].dst_host_rerror_rate), 2) +// 40
                         pow((t[i].dst_host_srv_rerror_rate - testData[j].dst_host_srv_rerror_rate), 2);

            distance[i] = sum;
            label[i] = t[i].label;
        }

        // Set the original values of K-nearest to the first k values.
        for(int a = 0; a < k; a++)
        {
            knnMinDistances[a] = distance[a];
            knnLabels[a] = label[a];
        }

        int tempIndex = -1;
        // Find the K-nearest neighbors to the jth point.
        for(int i = 0; i < tSize; i++)
        {
            double tempVal = distance[i];
            tempIndex = -1;
            // Find the max of any knnMinDistances that are > the ith distance.
            for(int b = 0; b < k; b++)
            {
                if(tempVal < knnMinDistances[b])
                {
                    tempVal = knnMinDistances[b];
                    tempIndex = b;
                }
            }
            // Replace the max distance with the ith distance, if the above loop found a point (as the ith distance is then closer).
            if(tempIndex != -1)
            {
                knnMinDistances[tempIndex] = distance[i];
                knnLabels[tempIndex] = label[i];
            }
        }

        memset(knnGuesses, 0, k); // Set the amount of all guesses to 0.
        int max = 0;              // The amount of guesses the max class has.
        double maxClass = 0;      // The class with the highest amount of guesses.
        // Determine the amount of guesses for each class.
        for(int a = 0; a < k; a++)
        {
            // Increase the guesses of the ath label by 1.
            int guess = knnLabels[a];
            knnGuesses[guess]++;
            // If that results in the amount of guesses being greater than the max, set the max to the new amount and class.
            if(knnGuesses[guess] > max)
            {
                max = knnGuesses[guess];
                maxClass = guess;
            }
        }

        int a = testData[j].label; // The actual label for the jth point.
        int b = maxClass;          // The guessed label for the jth point.
        confusionMatrix[a][b]++;   // Increase the confusion matrix by 1.

        if(globalRulesResults[j] == 4 && b != 4) // If the Warez signature detection said that particular element is an attack.
        {
            b = 4;
        }
        confusionMatrix2[a][b]++;   // Increase the confusion matrix by 1.

        if(j%100 == 0) // If the program is on the X000th entry, print out a progress counter.
        {
            cerr << j << endl;
        }
    }

    // Print out the final confusion matrix.
    for(int a = 0; a < confusionMatrixSize; a++)
    {
        int sum = 0;
        cout << endl;
        for(int b = 0; b < confusionMatrixSize; b++)
        {
            cout << confusionMatrix[a][b] << " ";
            sum = sum + confusionMatrix[a][b];
        }
    }

    // Print out the final confusion matrix 2.
    for(int a = 0; a < confusionMatrixSize; a++)
    {
        int sum = 0;
        cout << endl;
        for(int b = 0; b < confusionMatrixSize; b++)
        {
            cout << confusionMatrix2[a][b] << " ";
            sum = sum + confusionMatrix2[a][b];
        }
    }

    // Free the various allocated arrays.
    free(distance);
    free(label);
    free(knnGuesses);
    free(knnLabels);
    free(knnMinDistances);
}

/*
 * void printAllData(vector<networkTraffic> data)
 * Prints the entire data that has been taken in.
 */
void printAllData(vector<networkTraffic> data)
{
    for(size_t i = 0 ; i < data.size() ; ++i )
    {
        cout << data[i].duration << " " << data[i].protocol_type << " " << data[i].service << " " << data[i].flag << " " << data[i].src_bytes << endl;
        cout << data[i].dst_bytes << " " << data[i].land << " " << data[i].wrong_fragment << " " << data[i].urgent << " " << data[i].hot << endl;
        cout << data[i].num_failed_logins << " " << data[i].logged_in << " " << data[i].num_compromised << " " << data[i].root_shell << " " << data[i].su_attempted << endl;
        cout << data[i].num_root << " " << data[i].num_file_creations << " " << data[i].num_shells << " " << data[i].num_access_files << " " << data[i].num_outbound_cmds << endl;
        cout << data[i].is_host_login << " " << data[i].is_guest_login << " " << data[i].count << " " << data[i].srv_count << " " << data[i].serror_rate << endl;
        cout << data[i].srv_serror_rate  << " " << data[i].rerror_rate << " " << data[i].srv_rerror_rate << " " << data[i].same_srv_rate << " " << data[i].diff_srv_rate << endl;
        cout << data[i].srv_diff_host_rate << " " << data[i].dst_host_count  << " " <<  data[i].dst_host_srv_count << " " << data[i].dst_host_same_srv_rate << " " << data[i].dst_host_diff_srv_rate << endl;
        cout << data[i].dst_host_same_src_port_rate << " "  << data[i].dst_host_srv_diff_host_rate << " " << data[i].dst_host_serror_rate << " " << data[i].dst_host_srv_serror_rate << " " << data[i].dst_host_rerror_rate << endl;
        cout << data[i].dst_host_srv_rerror_rate << " " << data[i].label << endl << endl;
    }
}

/*
 * void rules(vector<networkTraffic> t)
 * Goes through a data set t and uses signatures to determine whether a line of data is a Warezclient or Warezmaster (attack type 4) attack.
 */
void rules(vector<networkTraffic> t)
{
    int tSize = t.size();
    int label = 0;
    double a = preProcessService("ftp") / (AMOUNT_OF_SERVICES - 1);
    double b = preProcessService("ftp_data") / (AMOUNT_OF_SERVICES - 1);
    double protocol = preProcessProtocol("tcp") / (AMOUNT_OF_PROTOCOLS - 1);
    double hot = 2 / HOT_MAX;
    double duration = 265 / DURATION_MAX;
    double duration2 = 5 / DURATION_MAX;
    double hot2 = 25 / HOT_MAX;

    double amountOfWarez = 0; // amount of guessed Warezclient/master attacks.
    double amountOfU2R = 0; // amount of total U2R attacks.

    for(int i = 0; i < tSize; i++)
    {
        label = 0;
        // Warezmaster
        // Rule 2.1a
        if(t[i].duration > duration && t[i].protocol_type == protocol && ((t[i].service == a) || (t[i].service == b)) && t[i].src_bytes > log10(265616) && t[i].dst_bytes == 0)
        {
            label = 4;
        }
        // Rule 2.1b
        else if (t[i].protocol_type == protocol && ((t[i].service == a) || (t[i].service == b)) && (t[i].hot > 0) && (t[i].hot <= hot) && (t[i].is_guest_login == 1))
        {
            label = 4;
        }
        // Rule C2.1a
        else if(t[i].duration > duration && t[i].dst_bytes <= log10(688) && (t[i].is_guest_login == 1))
        {
            label = 4;
        }
        // Rule C2.1b
        else if(t[i].src_bytes > log10(265616) && t[i].src_bytes > log10(283618))
        {
            label = 4;
        }

        // Warezclient
        // Rule 2.2
        if(t[i].duration > duration2 && t[i].protocol_type == protocol && ((t[i].service == a) || (t[i].service == b)) && (t[i].logged_in == 1 || t[i].is_guest_login == 1) && t[i].hot > hot2)
        {
            label = 4;
        }
        // Rule C2.2b
        else if(t[i].dst_bytes <= log10(3299) && t[i].hot > hot2)
        {
            label = 4;
        }

        if(t[i].label == 4)
        {
            amountOfWarez++;
        }
        if(label == 4)
        {
            amountOfU2R++;
        }
        globalRulesResults[i] = label;

    }
    //cerr << "Warez: " << amountOfU2R << " Total: " << amountOfWarez << " Percent: " << amountOfU2R / amountOfWarez << endl;
}

/*
 * vector<networkTraffic> getRandomData(int amount, vector<networkTraffic> t)
 * Chooses 'amount' random lines from the data vecotr.
 * Returns a vector<networkTraffic> with the randomly chosen data in it.
 */
vector<networkTraffic> getRandomData(int amount, vector<networkTraffic> t)
{
    int seed = (int) time(NULL);
    int size = t.size();

    vector<networkTraffic> t2;
    srand(seed);
    int randomNumber = rand() % size;
    bool hasBeenChosen[size];

    for(int i = 0; i < size; i++)
    {
        hasBeenChosen[i] = false;
    }

    for(int i = 0; i < amount; i++)
    {
        while(hasBeenChosen[randomNumber] == true)
        {
            randomNumber = rand() % size;
        }
        hasBeenChosen[randomNumber] = true;
        t2.push_back(t[randomNumber]);
    }
    return t2;
}

/*
 * vector<networkTraffic> inputData()
 * Takes in the data file into the program.
 * Uses "kddcup.data.txt" unless another file is input via command line arguments.
 * Returns a vector<networkTraffic> with the data in it.
 */
vector<networkTraffic> inputData(char* fileName)
{
    ifstream myfile (fileName);           // Loads in the data file.
    if(myfile.is_open() == false)
    {
        cerr << "Error opening file " << fileName << endl;
        exit(1);
    }
    networkTraffic t;                       // Structure to store the data entries in.
    vector<networkTraffic> data;            // Vector to store each network data entry in.
    int test = 0;                           // For loop counter.
    string line;                            // Individual entry in the file.
    int maxAmount = 2*SIZE_OF_10_PERCENT_FILE;
    string protocol_type;                   // Strings for the four string fields.
    string service;
    string flag;
    string label;

    // Reads in the file.
    while(myfile.good() == true && test < maxAmount)
    {
        getline(myfile, line);  // Gets the entry.
        stringstream s(line);   // Allows program to read from line like a stream.
        s.imbue(std::locale(std::locale(), new colon_separated_only())); // Not sure, but helps program work.
        // Take in a line of data.
        while ( s >> t.duration >> protocol_type >> service >> flag >> t.src_bytes >>
                t.dst_bytes >> t.land >> t.wrong_fragment >> t.urgent >> t.hot >>
                t.num_failed_logins >> t.logged_in >> t.num_compromised >> t.root_shell >> t.su_attempted >>
                t.num_root >> t.num_file_creations >> t.num_shells >> t.num_access_files >> t.num_outbound_cmds >>
                t.is_host_login >> t.is_guest_login >> t.count >> t.srv_count >> t.serror_rate >>
                t.srv_serror_rate >> t.rerror_rate >> t.srv_rerror_rate >> t.same_srv_rate >> t.diff_srv_rate >>
                t.srv_diff_host_rate >> t.dst_host_count >> t.dst_host_srv_count >> t.dst_host_same_srv_rate >> t.dst_host_diff_srv_rate >>
                t.dst_host_same_src_port_rate >> t.dst_host_srv_diff_host_rate >> t.dst_host_serror_rate >> t.dst_host_srv_serror_rate >> t.dst_host_rerror_rate >>
                t.dst_host_srv_rerror_rate >> label)
        {
            // Preprocessing data (linearly scaled).
            t.duration = t.duration / DURATION_MAX;
            t.wrong_fragment = t.wrong_fragment / WRONG_FRAGMENT_MAX;
            t.urgent = t.urgent / URGENT_MAX;
            t.hot = t.hot / HOT_MAX;
            t.num_failed_logins = t.num_failed_logins / NUM_FAILED_LOGINS_MAX;
            t.num_compromised = t.num_compromised / NUM_COMPROMISED_MAX;
            t.su_attempted = t.su_attempted / SU_ATTEMPTED_MAX;
            t.num_root = t.num_root / NUM_ROOT_MAX;
            t.num_file_creations = t.num_file_creations / NUM_FILE_CREATIONS_MAX;
            t.num_shells = t.num_shells / NUM_SHELLS_MAX;
            t.num_access_files = t.num_access_files / NUM_ACCESS_FILES_MAX;
            t.count = t.count / COUNT_MAX;
            t.srv_count = t.srv_count / SRV_COUNT_MAX;
            t.dst_host_count = t.dst_host_count / DST_HOST_COUNT_MAX;
            t.dst_host_srv_count = t.dst_host_srv_count / DST_HOST_SRV_COUNT_MAX;

            // Preprocessing data (logarithmically scalled).
            if(t.src_bytes != 0)
            {
                t.src_bytes = log10(t.src_bytes);
            }
            if(t.dst_bytes != 0)
            {
                t.dst_bytes = log10(t.dst_bytes);
            }
            // Preprocessing data (strings, maps to ints and linearly scaled).
            //label = label.substr(0, label.length()-1); // Removes the '.' from label.
            t.label = preProcessLabel(label);// / (AMOUNT_OF_LABELS - 1));
            t.protocol_type = (preProcessProtocol(protocol_type) / (AMOUNT_OF_PROTOCOLS - 1));
            t.service = (preProcessService(service) / (AMOUNT_OF_SERVICES - 1));
            t.flag = (preProcessFlag(flag) / (AMOUNT_OF_FLAGS - 1));

            data.push_back(t);  // Adds the entry to the vector.

        }
        if(test%1000 == 0) // If the program is on the X000th entry, print out a progress counter.
        {
            cerr << test << endl;
        }
        if(test%1000 == 600) // After the counter has been up, erase it so they don't eventually fill the screen.
        {
        }
        test++;
    }
    return data;
}

int main(int argc, char *argv[])
{
    // If the user inputs the training/testing files to be used.
    if(argc > 2)
    {
        INPUT_FILE = argv[1];
        TEST_FILE = argv[2];
    }

    vector<networkTraffic> data; // Vectors for the data sets
    vector<networkTraffic> data2;
    vector<networkTraffic> testData;
    vector<networkTraffic> testData2;

    data = inputData(INPUT_FILE); // Get the data from the data sets.
    testData = inputData(TEST_FILE);
    //data2 = inputData(INPUT_FILE_2);
    //testData2 = inputData(TEST_FILE_2);

    globalRulesResults = (int*) malloc(testData.size() * sizeof(int));
    int kStart = 1; // First k to test.
    int kEnd = 2;   // Last k to test.

    // Execute KNN.
    for(int k = kStart; k <= kEnd; k++)
    {
        rules(testData);
        cout << "K = " << k << endl;
        cout << INPUT_FILE << " " << TEST_FILE << endl;
        knn(data, testData, k);
        cout << endl;
    }

    // Free global resources.
    free(globalRulesResults);
    return 0;
}
