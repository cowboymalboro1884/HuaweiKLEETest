#include "std_testcase.h"

#include <unistd.h>
#include <fcntl.h>
#include <dlfcn.h>

#define FILENAME "/tmp/file.txt"

void CWE114_Process_Control__w32_char_file_01_bad() {
    char *data;

    char buff[100] = "";

    int fd = open(FILENAME, O_RDONLY);

    if (fd == -1) {
        perror("Cannot open file");
        return;
    }

    ssize_t n;
    do {
        n = read(fd, buff, sizeof(buff));
        if (n == -1) {
            perror("Error reading file");
            close(fd);
            return;
        }
    } while (n != 0);

    close(fd);

    data = buff;

    {
        void *handle;
        char *error;

        handle = dlopen(data, RTLD_NOW);
        if (handle != nullptr) {
            dlclose(handle);
            printf("Library loaded and freed successfully\n");
        } else {
            error = dlerror();
            printf("Unable to load library: %s\n", error);
        }
    }
}


/* goodG2B uses the GoodSource with the BadSink */
static void goodG2B() {
    char *data;
    char dataBuffer[100] = "";
    data = dataBuffer;
    /* FIX: Specify the full pathname for the library */
    strcpy(data, "/lib/x86_64-linux-gnu/libc.so.6");
    {
        void *handle;
        char *error;

        handle = dlopen(data, RTLD_NOW);
        if (handle != nullptr) {
            dlclose(handle);
            printf("Library loaded and freed successfully\n");
        } else {
            error = dlerror();
            printf("Unable to load library: %s\n", error);
        }

    }
}

void CWE114_Process_Control__w32_char_file_01_good() {
    goodG2B();
}


/* Below is the main(). It is only used when building this testcase on
 * its own for testing or for building a binary to use in testing binary
 * analysis tools. It is not used when compiling all the testcases as one
 * application, which is how source code analysis tools are tested.
 */



int main(int argc, char *argv[]) {
    /* seed randomness */
    srand((unsigned) time(NULL));
    printf("Calling good()... \n");
    CWE114_Process_Control__w32_char_file_01_good();
    printf("Finished good() \n");

    printf("Calling bad()...\n");
    CWE114_Process_Control__w32_char_file_01_bad();
    printf("Finished bad() \n");
    return 0;
}
