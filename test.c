#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
void func2();
void func2(){
    printf("in func2\n");
}
void func(char path[10], int a) {
    printf("in func\n");
    int fd = open(path, a);
}
int main() {
    int a = 123;
    char path[10] = "a.txt";
    func(path, a);
    void (*fp)();
    fp = &func2;
    fp();
}
