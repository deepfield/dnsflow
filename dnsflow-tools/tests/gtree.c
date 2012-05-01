#include <glib.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

char * strnchr(char * str, char ch, unsigned int len)
{
	char * idx;
	idx = strchr(str, ch);
	if(idx - str >= len || !idx)
		return 0;
	return idx;
}

void swapchp(char * a, char *b)
{
	char c = *a;
	*a = *b;
	*b = c;
}

int max(int a, int b)
{
	return a > b ? a : b;
}

void reverse(char * str, int len)
{
	char * start = str;
	char * end = str + len - 1;

	while(start < end)
	{
		swapchp(start, end);
		start++;
		end--;
	}
}
	
//checks if the first len characters in b are in a's frist len_a characters
char * strstrn(char * a, char * b, int len_b, int len_a)
{
	char tmp = b[len_b];
	b[len_b] = '\0';
	char * ret strstr(a, b)
	b[len_b] = tmp;
	if(ret - a >= len_a)
		return 0;
	return ret;
}

//a is key to match
//b is user key with possible wildcard '*'
int isMatch(char * a, char *b, int a_len, int b_len)
{
	//error cases
	if(!a || !b || a_len < 0 || b_len < 0)
		return 0;

	//it's nothing left to check
	if(a_len == 0 || b_len == 0)
		return 1;

	//find first star location
	char * star = strnchr(b,'*', b_len);
	//no star
	if(!star)
	{
		return strncmp(a, b, max(a_len,b_len));
	}
	//star is in front
	//keep trying to find a match until we hit end of string or a star is encountered.
	else if(star - b == 0)
	{
		char * next_star = strnchr(b, '*', b_len);
		//case1 another star exists in b
		if(next_star)
		{
			int dist_to_next_star = next_star - star;
			int fix_chars_len = dist_to_next_star - 1;
			//try to find match in characters of a
			char * match = strstrn(b, a, a_len, dist_to_next_star);

		}
		//case2 no other stars exist in b
		else
		{

		}

	}
	//star is at end
	else if(star - b == strlen(b) - 1)
	{
		return strncmp(a,b, b_len);
	}
	//star is in middle, or front of word
	else
	{
		int star_idx = star - b;

		//first half of word including star
		int b_len_first_half = star_idx;
		a_len = a_len - b_len_first_half;

		return isMatch(a, b, b_len_first_half, b_len_first_half) &&
			isMatch(a + b_len_first_half, b + b_len_first_half, a_len, 
					b_len - b_len_first_half);
	}
	//should never get here
	return 0;
}

gint strcompare(gconstpointer a, gconstpointer b)
{
	printf("a is %s, and b is %s\n", (char *) a, (char *)b);
	char * idx = 0;
	if(idx = strchr((char*)a, '*'))
	{
		//case of * in begining
		if((idx - (char *)a) == 0)
			//reverse b
			return strncmp(a, b, idx - (char *)a);
		// of * at end
		if(idx - (char *)a == strlen(a)) 
			;
	}
	return strcmp(a,b);
}

int main()
{
	GTree * tree = g_tree_new(strcompare);

	char * str3 = "hello";
	char * str2 = "bye";
	char * str1 = "hel*";

	int value = 1;
	gpointer key;

	printf("insterting into gtree\n");

	g_tree_insert(tree, str1, &value);
	g_tree_insert(tree, str2, &value);

	printf("testing tree\n");

	key = g_tree_lookup(tree, str3);
	if(key)
		printf("%s found\n", str3);
	else
		printf("%s not found\n", str3);

	key = g_tree_lookup(tree, str2);

	if(key)
		printf("%s found\n", str2);
	else
		printf("%s not found\n", str2);

	return 0;
}
