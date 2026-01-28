#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>


int main(){
    pid_t pid = fork();
    if (pid == -1){
        printf("error\n");
        return 0;
    }
    else if (pid == 0){
        printf("fils\n");
        while (true){
            printf("je suis dans le fils");
            getchar();
        }
        return 0;
    }
    else {
        printf("pere\n");
        while (true){
            printf("je suis dans le pere");
            getchar();
        }
        return 0;
    }
}

//https://github.com/snare/voltron