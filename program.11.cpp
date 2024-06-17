#include <stdio.h>

// Function to calculate GCD using the Euclidean Algorithm
int gcd(int a, int b) {
    while (b != 0) {
        int t = b;
        b = a % b;
        a = t;
    }
    return a;
}

int main() {
    int num1, num2;

    // Prompt the user to enter two integers
    printf("Enter two integers: ");
    scanf("%d %d", &num1, &num2);

    // Calculate GCD
    int result = gcd(num1, num2);

    // Display the result
    printf("GCD of %d and %d is %d\n", num1, num2, result);

    return 0;
}

