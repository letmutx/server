#define _GNU_SOURCE

#include <assert.h>
#include <ctype.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <sys/sendfile.h>

#define USER_FILE "db/users"
#define USER_BLOCK_SIZE (2048)
#define USER_FILE_SIZE (32 * 1024 * 1024)
#define USER_BV_SIZE (USER_FILE_SIZE / USER_BLOCK_SIZE / 8)
#define USER_BLOCKS_TOTAL (USER_FILE_SIZE / USER_BLOCK_SIZE)

#define MSG_FILE "db/msgstore"
#define MSG_BLOCK_SIZE (256)
#define	MSG_FILE_SIZE (16 * 1024 * 1024)
#define MSG_BV_SIZE (MSG_FILE_SIZE / MSG_BLOCK_SIZE / 8)
#define MSG_BLOCKS_TOTAL (MSG_FILE_SIZE / MSG_BLOCK_SIZE)

#define FL_FILE "db/blobs"
#define FL_BLOCK_SIZE (4096)
#define FL_FILE_SIZE (1024 * 1024 * 1024)
#define FL_BV_SIZE (FL_FILE_SIZE / FL_BLOCK_SIZE / 8)
#define FL_BLOCKS_TOTAL (FL_FILE_SIZE / FL_BLOCK_SIZE)

#define PORT "8000"

/* compressed trie structure */
struct patterns {
	char **paths;				/* string part of url */
	int len_paths;
	void *(*routine)(void *);		/* routine to call on match */
	struct patterns *numbernext;		/* next node if current is a number */
	struct patterns **strnext;		/* next nodes for different paths */
};

struct match {
	int *arr;				/* matched numbers in the order they are found */
	void *(*routine)(void *);		/* the handler to call on match of the url */
	int len_arr;				/* length of the array */
};

struct header {
	char *key;				/* key of the HTTP header */
	char *value;				/* value of the HTTP header */
	struct header *next;			/* linked list next part */
};

struct reqheaders {
	char *action;				/* HTTP action of that request */
	char *url;				/* url part of that request */
	struct header *data;			/* GET data, if any */
	struct header *hdrs[8];			/* hash table of headers */
};

struct request {
	int clientfd;
	struct reqheaders *reqh;
	int *params;
	int len_params;
};

struct user {
	int id;				/* id of the user */
	int roles;			/* police, doctor, ... */
	off_t first_file_location;	/* blob store location */
	char username[256];
	char password[256];
	int top_app;			/* top index on appointments */
	int appointments[182];		/* number of days in 6 months */
	char last_updated[100];		/* date string, when appointments is last updated */
	char unused[USER_BLOCK_SIZE - 256 * 2 - 4 * 3 - 182 * 4 - 8 - 100];
};

struct usermeta {
	int id;
	char unused[USER_BLOCK_SIZE - 4];
};

struct messagemeta {
	off_t first_category;
	int category_count;
	int messages_count;
	int replies_count;
	char unused[MSG_BLOCK_SIZE - 8 - 3 * 4];
};

struct filemeta {
	int file_count;
	int remaining_blocks;
	char unused[FL_BLOCK_SIZE - 2 * 4];
};

struct category {
	int cat_id;
	int owner_id;
	off_t first_message;		/* message of this category */
	off_t next_category;
	char name[50];
	char description[MSG_BLOCK_SIZE - 50 - 4 - 3 * 8];
};

struct message {
	int msg_id;
	int owner_id;
	off_t next_message;
	off_t first_reply;			/* replies of that message */
	char content[MSG_BLOCK_SIZE - 3 * 8];
};

struct reply {
	int reply_id;
	int owner_id;
	off_t next_reply;		/* linked list */
	char content[MSG_BLOCK_SIZE - 4 * 2 - 8];
};

/* file head structure uses linked list of indexed allocation blocks */
/* all values except blocks and next_blocks are valid only in the first head of the file */
struct filehead {
	int file_id;				
	int owner_id;
	char name[256];				/* name of the file */
	ssize_t filesize;
	off_t next_file;			/* next file of that user */
	off_t next_blocks;			/* if file size > 476 * 4096 bytes, add to linked list of filehead */
	off_t blocks[476];			/* location of blocks */
};

/* helpers for url patterns */

struct patterns *load_urls(FILE *fp);
struct patterns *add_pattern(struct patterns *p, char *line, void *(*routine)(void *));
struct match *match_url(struct patterns *current, char *url);

void freepatterns(struct patterns *t);
void freematch(struct match *m);

/* helpers for url patterns */

/* parsing request headers */

char *readline(int sockfd);						/* read a line without newline or formfeed */
struct header *parse_request_data(char *buffer);			/* parse get or post data in buffer, requires & at end */
int parse_status_line(char *statusline, struct reqheaders *reqh);	/* extract url, action, get data if any */
struct reqheaders *parse_request(int clientfd);				/* read request headers, post data if any */

int hash(char *key);							/* hash function for header hashtable */
char *trim(char *str, int len);						/* removes extr spaces at start and end, resize str */
void break_into_key_value(char *hdr, char **key, char **value);		/* break header into key, value */
struct header *header_insert(struct header *data, char *key, char *val);/* add a header into head linked list */
void add_header(struct header *hashtable[], char *key, char *value);	/* add header into hashtable */
char *get_header_value(struct header *hashtable[], char *key);
char *get_header(struct header *header, char *key);
struct header *get_cookie_data(struct request *req);
ssize_t get_multipart_data(struct request *req, char **filedata);

void freeheader(struct header *h);
void freereqheaders(struct reqheaders *reqh);
void freerequest(struct request *req);

/* parsing request headers */

/* program flow helpers */

int bindaddress(char *port);
void *listener(void *arg);

/* program flow helpers */

/* initialization */

void create_files(char *filename, ssize_t filesize);
void initialize_bit_vector(char *filename, int total_blocks, int filled_blocks);

/* initialization */

/* handlers for requests */

void *http404(void *arg);
void *http415(void *arg);
void *http507(void *req);
void *http_redirect(struct request *req, char *new_url, char *additional_headers);

void *current_user_view(void *arg);
void *user_detail_view(void *arg);
void *user_update_view(void *arg);
void *home_page_handler(void *arg);
void *signup_page_handler(void *arg);
void *login_page_handler(void *arg);
void *loginfail_handler(void *arg);
void *logout_handler(void *arg);

void *category_create_view(void *arg);
void *category_detail_view(void *arg);
void *category_list_view(void *arg);
void *category_delete_view(void *arg);

void *message_create_view(void *arg);
void *message_list_view(void *arg);
void *message_delete_view(void *arg);

void *reply_create_view(void *arg);
void *reply_list_view(void *arg);
void *reply_delete_view(void *arg);

void *files_upload_view(void *arg);
void *files_list_view(void *arg);
void *files_download_view(void *arg);
void *files_delete_view(void *arg);

void *serviceman_category_view(void *arg);
void *serviceman_list_view(void *arg);
void *appointment_list_view(void *arg);
/* handlers for requests */

/* managing users */

int add_user(struct user *u);
struct user *get_user(int id);
void update_user(struct user *u);
int logged_in(struct request *req);
int authenticate(char *username, char *password);
struct user **get_all_users(int role, int *len);
char *serialize_user(struct user *u);
char *serialize_user_array(struct user **u, int len);
struct user *get_user_from_request(struct request *req);
struct user *create_new_user(char *username, char *password, int roles, char *date);

/* managing users */

/* message store */
struct category *new_category(char *name, char *description, int owner_id);
char *serialize_category(struct category *category);
char *serialize_category_array(struct category **categories, int len);
int add_category(struct category *category);
struct category **get_all_categories(int *len);
struct category *get_category(int category_id);
int delete_category(int category_id, int owner_id);

struct message *new_message(char *content, int owner_id);
int add_message(struct message *m, int category_id);
struct message **get_all_messages(int category_id, int *len);
char *serialize_message_array(struct message **messages, int len);
char *serialize_message(struct message *message);
int delete_message(int category_id, int message_id, int owner_id);
void delete_all_messages(int fd, off_t message, char *block_status);

struct reply *new_reply(char *content, int owner_id);
int add_reply(struct reply *m, int category_id, int msg_id);
char *serialize_reply_array(struct reply **replys, int len);
char *serialize_reply(struct reply *reply);
struct reply **get_all_replies(int category_id, int msg_id, int *len);
int delete_reply(int category_id, int msg_id, int reply_id, int owner_id);
void delete_all_replies(int fd, off_t reply, char *block_status);

/* message store */

/* blob store */

int add_file(char *filedata, ssize_t filesize, char *filename, int owner_id);
void initialize_blob_file(char *filename, int total_blocks, int filled_blocks, int free_blocks);
struct filehead **get_all_files(int owner_id, int *len);
ssize_t get_file(int user_id, int file_id, char **filedata, char **filename);
int delete_file(int user_id, int file_id);

char *serialize_file_array(struct filehead **fheads, int len);
char *serialize_file(struct filehead *fheads);

/* blob store */

/* calendar store */

#define POLICE (1)
#define DOCTOR (2)
#define TEACHER (4)
#define ENGINEER (8)
#define LAWYER (16)
#define ARTIST (32)
#define SCIENTIST (64)
#define MUSICIAN (128)
#define BANKER (256)
#define ELECTRICIAN (512)

#define is_policeman(u) ((u->roles) & POLICE)
#define is_doctor(u) ((u->roles) & DOCTOR)
#define is_engineer(u) ((u->roles) & ENGINEER)
#define is_teacher(u) ((u->roles) & TEACHER)
#define is_lawyer(u) ((u->roles) & LAWYER)
#define is_artist(u) ((u->roles) & ARTIST)
#define is_scientist(u) ((u->roles) & SCIENTIST)
#define is_musician(u) ((u->roles) & MUSICIAN)
#define is_banker(u) ((u->roles) & BANKER)
#define is_electrician(u) ((u->roles) & ELECTRICIAN)

#define add_role(role, magic) ((role) | (magic))

/* calendar store */

/* bit vector manipulation */

void set_block_full(char *bitvector, int block_number);
int is_block_free(char *bitvector, int block_number);
void set_block_empty(char *bitvector, int block_number);

/* bitvector manipulation */

int main(int argc, char *argv[]) {
	int sockfd;
	char *port;
	pthread_t l;

	sockfd = bindaddress(PORT);

	// create all the files with their respective sizes
	create_files(FL_FILE, FL_FILE_SIZE);
	create_files(USER_FILE, USER_FILE_SIZE);
	create_files(FL_FILE, FL_FILE_SIZE);

	// initialize db files with bitvectors if not always present
	initialize_bit_vector(USER_FILE, USER_BLOCKS_TOTAL, USER_BV_SIZE / USER_BLOCK_SIZE + 1); // bitvector + meta block
	initialize_bit_vector(MSG_FILE, MSG_BLOCKS_TOTAL, MSG_BV_SIZE / MSG_BLOCK_SIZE + 1);	 // bitvector + meta block
	initialize_blob_file(FL_FILE, FL_BLOCKS_TOTAL, FL_BV_SIZE / FL_BLOCK_SIZE + 1,
			     FL_BLOCKS_TOTAL - FL_BV_SIZE / FL_BLOCK_SIZE + 1);

	if (sockfd == -1) {
		fprintf(stderr, "bindaddress: cannot bind address\n");
		return 2;
	}

	// jump into the listener thread
	pthread_create(&l, NULL, listener, &sockfd);

	// main thread should never exit
	pthread_join(l, NULL);

	return 0;
}

void *listener(void *arg) {
	FILE *urlsfile; 
	struct match *m;
	struct reqheaders *reqh;
	int server_sock = *(int *)arg, clientfd, rv;
	struct sockaddr_storage client;
	socklen_t size = sizeof(client);
	struct patterns *url_patterns;
	struct request *req;
	pthread_t id;


	urlsfile = fopen("urls.txt", "r");

	url_patterns = load_urls(urlsfile);

	fclose(urlsfile);
	// if a request is received, parse the request headers
	// depending upon the url, go to the respective handler using match_url
	// start with the user login handler
	// later add more handlers
	while (1) {
		usleep(250);
		m = NULL;
		rv = listen(server_sock, 128);

		if (rv == -1) {
			fprintf(stderr, "listen: returned -1\n");
			continue;
		}

		clientfd = accept(server_sock, (struct sockaddr *)&client, &size);

		if (clientfd != -1) {
			fprintf(stderr, "accept: connected\n");
		}
		else {
			continue;
		}

		reqh = parse_request(clientfd);

		// temporary fix
		if (reqh == NULL) {
			fprintf(stderr, "reqh: null\n");
			close(clientfd);
			continue;
		}

		m = match_url(url_patterns, reqh->url);

		req = calloc(1, sizeof(*req));

		req->reqh = reqh;
		req->clientfd = clientfd;

		if (!m) {
			pthread_create(&id, NULL, http404, req);
		}
		else {
			req->params = m->arr;
			req->len_params = m->len_arr;
			pthread_create(&id, NULL, m->routine, req);
		}

		free(m);

	}
	pthread_exit(NULL);
}

struct match *match_url(struct patterns *current, char *url) {
	char *token, *endptr = NULL;
	struct match *m = calloc(1, sizeof(*m));

	token = strtok(url, "/");

	while (token) {
		int b = 0;
		int num = strtol(token, &endptr, 10);
		if (endptr != token) {
			if (!current->numbernext) {
				free(m);
				return NULL;
			}
			m->len_arr++;
			m->arr = realloc(m->arr, sizeof(int) * m->len_arr);
			m->arr[m->len_arr - 1] = num;
			current = current->numbernext;
			token = strtok(NULL, "/");
			continue;
		}
		if (!current->paths) {
			free(m);
			return NULL;
		}
		for (int i = 0; i < current->len_paths; i++) {
			if (!strcmp(current->paths[i], token)) {
				b = 1;
				current = current->strnext[i];
				break;
			}
		}

		if (b) {
			token = strtok(NULL, "/");
			continue;
		}
		else {
			free(m);
			return NULL;
		}
	}

	if (!current || !current->routine) {
		free(m);
		return NULL;
	}

	m->routine = current->routine;
	return m;

}

void freepatterns(struct patterns *t) {
	if (t == NULL) {
		return;
	}
	if (t->numbernext) {
		freepatterns(t->numbernext);
	}
	for (int i = 0; i < t->len_paths; i++) {
		freepatterns(t->strnext[i]);
	}

	for (int i = 0; i < t->len_paths; i++) {
		free(t->paths[i]);
	}
	free(t->strnext);
	free(t->paths);
	free(t);
	return;
}

void freematch(struct match *m) {
	if (m->len_arr) {
		free(m->arr);
	}
	free(m);
	return ;
}

int bindaddress(char *port) {
	int sockfd, rv, reuse = 1;
	struct addrinfo hints, *server, *iter;

	memset(&hints, 0, sizeof(hints));

	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_PASSIVE;

	rv = getaddrinfo(NULL, port, &hints, &server);

	if (rv) {
		fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
		return -1;
	}

	for (iter = server; iter; iter = iter->ai_next) {
		sockfd = socket(iter->ai_family, iter->ai_socktype | SOCK_NONBLOCK, iter->ai_protocol);

		if (sockfd == -1) {
			fprintf(stderr, "socket: returned -1\n");
			continue;
		}

		rv = setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(int));

		if (rv == -1) {
			fprintf(stderr, "setsockopt: failed\n");
		}

		rv = bind(sockfd, iter->ai_addr, iter->ai_addrlen);

		if (rv == -1) {
			close(sockfd);
			fprintf(stderr, "bind: failed to bind the socket\n");
			continue;
		}
		else {
			break;
		}
	}

	if (!iter) {
		sockfd = -1;
	}

	freeaddrinfo(server);

	return sockfd;
}

struct patterns *add_pattern(struct patterns *p, char *line, void *(*routine)(void *)) {
	char *token = NULL;
	struct patterns *current;
	static char *symbols[] = {"<number>"};

	if (!p) {
		p = calloc(1, sizeof(*p));
	}

	token = strtok(line, "/");

	current = p;

	while (token) {
		int b = 0;
		if (!strcmp(token, symbols[0])) {
			if (!current->numbernext) {
				current->numbernext = calloc(1, sizeof(*p));
			}
			current = current->numbernext;
			token = strtok(NULL, "/");
			continue;
		}
		for (int i = 0; i < current->len_paths; i++) {
			if (strcmp(token, current->paths[i]) == 0) {
				current = current->strnext[i];
				b = 1;
				break;
			}
		}
		if (b) {
			token = strtok(NULL, "/");
			continue;
		}
		current->len_paths++;
		current->paths = realloc(current->paths, sizeof(char *) * current->len_paths);
		current->paths[current->len_paths - 1] = malloc(strlen(token) + 1);
		strcpy(current->paths[current->len_paths - 1], token);
		current->strnext = realloc(current->strnext, sizeof(struct patterns *) * current->len_paths);
		current->strnext[current->len_paths - 1] = calloc(1, sizeof(*p));
		current = current->strnext[current->len_paths - 1];
		token = strtok(NULL, "/");
	}

	current->routine = routine;

	return p;
}

/* loads urls from file into the pattern structure, with the 
 * corresponding views to be called on successful match on the end 
 */
struct patterns *load_urls(FILE *fp) {
	int i = 0;
	struct patterns *urls = NULL;
	char *line = NULL;
	size_t len;
	ssize_t temp = 0;

	void *(*routines[])(void *) = { 
		home_page_handler, signup_page_handler, login_page_handler, loginfail_handler, logout_handler,
		category_create_view, category_list_view, category_detail_view, message_create_view, message_list_view,
		reply_create_view, reply_list_view, category_delete_view, message_delete_view, reply_delete_view,
		files_upload_view, files_list_view, files_download_view, files_delete_view, serviceman_category_view,
		serviceman_list_view, user_detail_view, user_update_view, current_user_view, appointment_list_view
	};

	while ((len = getline(&line, &temp, fp)) != -1) {
		line[len - 1] = line[len - 1] == '\n' ? 0 : line[len - 1];
		urls = add_pattern(urls, line, routines[i++]);
	}

	free(line);
	return urls;
}

// parse the request status line
int parse_status_line(char *statusline, struct reqheaders *reqh) {
	int keyval_len;
	float f;
	char *token, *saveptr, *getdata, *saveptr2, *keyval, *temp;

	token = strtok_r(statusline, " ", &saveptr);

	if (!token) {
		return 0;
	}

	reqh->action = malloc(strlen(token) + 1);
	strcpy(reqh->action, token);

	// start of the url along with GET data
	token = strtok_r(NULL, " ", &saveptr);

	if (!token) {
		return 0;
	}

	// the actual url part without GET data
	getdata = strtok_r(token, "?", &saveptr2);

	// there is no GET data
	reqh->url = malloc(strlen(getdata) + 1);
	strcpy(reqh->url, getdata);

	// GET data key value pairs
	keyval = strtok_r(NULL, " ", &saveptr2);
	while (keyval) {
		keyval_len = strlen(keyval);
		// append a & and send to parse_request_data
		temp = malloc(keyval_len + 1 + 1);
		strcpy(temp, keyval);
		temp[keyval_len] = '&';
		temp[keyval_len + 1] = 0;
		reqh->data = parse_request_data(temp);
		free(temp);
		keyval = strtok_r(NULL, " ", &saveptr2);
	}

	// HTTP version information
	token = strtok_r(NULL, " ", &saveptr);
	token = strtok_r(token, "/", &saveptr);
	if (strcmp(token, "HTTP")) {
		return 0;
	}
	token = strtok_r(NULL, " ", &saveptr);

	// version information
	f = strtof(token, &saveptr);

	if (saveptr == token || (f != 1.1f && f != 1.0f && f != 2.0f)) {
		return 0;
	}

	return 1;
}

/* only works for the form in files_upload_view */
ssize_t get_multipart_data(struct request *req, char **filedata) {
	char *endptr = NULL;
	int clientfd = req->clientfd;
	char *cl = get_header_value(req->reqh->hdrs, "Content-Length");
	char *ct = get_header_value(req->reqh->hdrs, "Content-Type");
	char *temp = strstr(ct, "boundary=") + sizeof("boundary=");
	char *boundary = malloc(strlen(temp) + 1);
	strcpy(boundary, temp);
	ssize_t content_length = strtoll(cl, &endptr, 10);
	char *request_data = malloc(content_length);
	char buf[512];
	int numbytes, i = 0;
	ssize_t total = 0;
	// read in chunks of 512 bytes
	while (total < content_length && (numbytes = recv(clientfd, buf, 512, 0)) > 0) {
		for (int j = 0; j < numbytes; j++) {
			request_data[i++] = buf[j];
		}
		total += numbytes;
	}
	if (total != content_length) {
		puts("error: total != content_length");
	}
	temp = strstr(request_data, "filename=");
	temp += strlen("filename=") + 1;
	i = 0;
	char *key = malloc(sizeof("filename"));
	strcpy(key, "filename");
	char *filename = malloc(256);
	while (*temp != '"') {
		filename[i++] = *temp;
		temp++;
	}
	filename[i] = 0;
	add_header(req->reqh->hdrs, key, filename);
	char *start_of_file = strstr(temp, "\r\n\r\n") + 4;
	// check for the boundary
	char *end_of_file = request_data + content_length - strlen(boundary) - 5;
	free(boundary);
	// move back till you hit a CRLF, that's the end of file data
	while (end_of_file > start_of_file && !(*end_of_file == '\r' && *(end_of_file + 1) == '\n')) {
		end_of_file--;
	}
	ssize_t filesize = end_of_file - start_of_file;
	// remove everything other than filedata
	for (ssize_t i = 0; i < filesize; i++) {
		request_data[i] = start_of_file[i];
	}
	*filedata = request_data = realloc(request_data, filesize);
	return filesize;
}

// get all the roles in a request post data
int get_roles(struct header *post_data) {
	int role = 0;
	static char *roles[] = { "policeman", "doctor", "engineer", "teacher", "lawyer", "artist",
				"scientist", "musician", "banker", "electrician" };
	static int magic[] = { POLICE, DOCTOR, TEACHER, ENGINEER, LAWYER, ARTIST, SCIENTIST, MUSICIAN, BANKER, ELECTRICIAN};
	for (int i = 0; i < 10; i++) {
		char *temp = get_header(post_data, roles[i]);
		if (temp) {
			role = add_role(role, magic[i]);
			free(temp);
		}
	}
	return role;
}

// return a linked list of key value pairs read from clientfd
struct header *get_post_data(int clientfd) {
	struct header *post_data;
	char buf, *data = malloc(2);
	int size = 2, i = 0;
	while (recv(clientfd, &buf, 1, MSG_DONTWAIT) > 0) {
		if (i == size) {
			size += 200;
			data = realloc(data, size);
		}
		data[i++] = buf;
	}
	// parse_request_data requires & at the end
	data[i++] = '&';
	data[i] = 0;
	data = realloc(data, i + 1);
	// parse the request data
	post_data = parse_request_data(data);
	free(data);
	return post_data;
}

// parse a request data form encoded data
struct reqheaders *parse_request(int clientfd) {
	struct reqheaders *reqh;
	char *hdr, *key, *value;
	char *data = NULL, buf;
	int size = 0, i = 0;

	// read the status line
	hdr = readline(clientfd);

	if (!hdr) {
		return NULL;
	}

	reqh = calloc(1, sizeof(*reqh));

	assert (reqh != NULL);

	if (!parse_status_line(hdr, reqh)) {
		return NULL;
	}

	free(hdr);

	// read the remaining headers, into a list
	while (hdr = readline(clientfd)) {
		break_into_key_value(hdr, &key, &value);
		add_header(reqh->hdrs, key, value);
		free(hdr);
	}

	return reqh;
}

// parse the get or post request data, requires an & at the end
struct header *parse_request_data(char *buffer) {
	struct header *data;
	char *key, *value, *k, *val;
	char *saveptr, *saveptr2;

	if (!buffer) {
		return NULL;
	}

	data = NULL;
	char *kv = strtok_r(buffer, "&", &saveptr);
	while (kv) {
		k = strtok_r(kv, "=", &saveptr2);
		val = strtok_r(NULL, "", &saveptr2);
		key = malloc(strlen(k) + 1);
		strcpy(key, k);
		value = malloc(strlen(val) + 1);
		strcpy(value, val);
		data = header_insert(data, key, value);
		kv = strtok_r(NULL, "&", &saveptr);
	}

	return data;
}

// break a header into key and value, trimming them at the end and beginning
void break_into_key_value(char *hdr, char **key, char **value) {
	int len;
	char *token, *saveptr;

	token = strtok_r(hdr, ":", &saveptr);

	len = strlen(token);
	*key = malloc(len + 1);
	strcpy(*key, token);
	*key = trim(*key, len);

	token = strtok_r(NULL, "", &saveptr);
	len = strlen(token);
	*value = malloc(len + 1);
	strcpy(*value, token);
	*value = trim(*value, len);

	return;
}

// linked list addition
struct header *header_insert(struct header *data, char *key, char *val) {
	struct header *new = calloc(1, sizeof(*new));
	struct header *cur;
	new->key = key;
	new->value = val;
	new->next = NULL;

	if (!data) {
		data = new;
	}
	else {
		// insert at the end
		cur = data;
		while (cur->next) {
			cur = cur->next;
		}
		cur->next = new;
	}
	return data;
}

// insert into the hashtable of headers, separate chaining with linked lists
void add_header(struct header *header[], char *key, char *value) {
	int h = hash(key);
	header[h] = header_insert(header[h], key, value);
	return;
}

// get a user from request
struct user *get_user_from_request(struct request *req) {
	struct user *u = calloc(1, sizeof(*u));
	char buf, *saveptr, *saveptr2;
	int size = 2, i = 0;
	char *data = malloc(2);
	char *content_length = get_header_value(req->reqh->hdrs, "Content-Length");
	int cl = atoi(content_length);
	int total_bytes_read = 0;
	while (total_bytes_read < cl && recv(req->clientfd, &buf, 1, 0) > 0) {
		if (i == size) {
			size += 200;
			data = realloc(data, size);
		}
		data[i++] = buf;
		total_bytes_read++;
	}
	data[i++] = '&';
	data[i] = 0;
	data = realloc(data, i + 1);
	char *kv = strtok_r(data, "&", &saveptr);
	i = 0;
	while (kv) {
		char *key = strtok_r(kv, "=", &saveptr2);
		char *val = strtok_r(NULL, "", &saveptr2);

		if (!strcmp(key, "id")) {
			u->id = atoi(val);
		}
		else if (strstr(key, "appointment")) {
			u->appointments[i++] = atoi(val);
		}
		else if (strstr(key, "current")) {
			u->top_app = atoi(val);
		}
		else if (!strcmp(key, "last_updated")) {
			strcpy(u->last_updated, val);
		}
		kv = strtok_r(NULL, "&", &saveptr);
	}

	free(data);
	return u;
}

// simple hash for hash table
int hash(char *key) {
	int h = 0;

	while (*key) {
		h += *key;
		key++;
	}

	return h % 8;
}

// search in the linked list of headers
char *get_header(struct header *header, char *key) {
	char *val;

	while (header) {
		if (!strcmp(header->key, key)) {
			val = malloc(strlen(header->value) + 1);
			strcpy(val, header->value);
			return val;
		}
		header = header->next;
	}
	return NULL;
}

// read the cookie data, doesn't work for everything
struct header *get_cookie_data(struct request *req) {
	int len;
	// get Cookie header
	char *cookie_buf = get_header_value(req->reqh->hdrs, "Cookie");

	if (!cookie_buf) {
		return NULL;
	}

	len = strlen(cookie_buf) + 1 + 1;

	cookie_buf = realloc(cookie_buf, len);

	cookie_buf[len - 1] = 0;
	cookie_buf[len - 2] = '&';

	while (*cookie_buf++ != '=') 	// skip the name of the cookie and the '='
		;

	// cookie data follows POST data format
	return parse_request_data(cookie_buf);
}

// search for headers in hashtable
char *get_header_value(struct header *hashtable[], char *key) {
	int h = hash(key);

	return get_header(hashtable[h], key);
}

// trim a string at the beginning and end
char *trim(char *str, int len) {
	int i = 0, j = 0;

	while (i < len && isspace(str[i])) {
		i++;
	}

	while (i > j && str[i]) {
		str[j++] = str[i];
		str[i++] = ' ';
	}

	i = len - 1;
	while (i > -1 && isspace(str[i])) {
		i--;
	}
	str[i + 1] = 0;

	str = realloc(str, i + 2);

	return str;
}

// read until a CLRF from sockfd, return the line with CLRF
char *readline(int sockfd) {
	int newline = 0;
	char cur;
	long size = 200, i = 0;
	char *line = malloc(size);

	while (recv(sockfd, &cur, 1, 0) > 0) {
		if (cur == '\r') {
			newline = 1;
		}
		else if (newline && cur == '\n') {
			newline = 0;
			break;
		}
		else {
			line[i++] = cur;
			newline = 0;
		}

		if (i == size) {
			size += 200;
			line = realloc(line, size);
		}
	}
	line[i] = 0;
	line = realloc(line, i ? i + 1 : i);
	return line;
}

// free the individual headers
void freeheader(struct header *hdr) {
	if (!hdr) {
		return;
	}
	freeheader(hdr->next);
	free(hdr->key);
	free(hdr->value);
	free(hdr);
	return;
}

// free the headers and actin, get data
void freereqheaders(struct reqheaders *reqh) {
	free(reqh->action);
	freeheader(reqh->data);
	for (int i = 0; i < 8; i++) {
		freeheader(reqh->hdrs[i]);
	}
	free(reqh);
	return;
}

// free the request object
void freerequest(struct request *req) {
	freereqheaders(req->reqh);
	free(req->params);
	free(req);
}

// returns a HTTP 400 response
void *http400(void *arg) {
	struct request *req = arg;
	int fd = open("static/400.html", O_RDONLY);
	off_t size = lseek(fd, 0, SEEK_END);
	lseek(fd, 0, SEEK_SET);

	dprintf(req->clientfd, "HTTP/1.0 400 Bad Request\r\n");
	dprintf(req->clientfd, "Content-Type: text/html\r\n");
	dprintf(req->clientfd, "Content-Length: %ld\r\n", size);
	dprintf(req->clientfd, "\r\n");
	sendfile(req->clientfd, fd, NULL, size);

	close(fd);
	close(req->clientfd);
	freerequest(req);

	return NULL;
}

// returns a HTTP 404 response
void *http404(void *arg) {
	struct request *req = arg;
	int fd = open("static/404.html", O_RDONLY);
	off_t size = lseek(fd, 0, SEEK_END);
	lseek(fd, 0, SEEK_SET);

	dprintf(req->clientfd, "HTTP/1.0 404 Not Found\r\n");
	dprintf(req->clientfd, "Content-Type: text/html\r\n");
	dprintf(req->clientfd, "Content-Length: %ld\r\n", size);
	dprintf(req->clientfd, "\r\n");
	sendfile(req->clientfd, fd, NULL, size);

	close(fd);
	close(req->clientfd);
	freerequest(req);

	return NULL;
}

// the home page of the site
void *home_page_handler(void *arg) {
	int fd;
	off_t filesize;
	struct request *req = arg;

	// check if user is logged in else redirect to login page
	if (!logged_in(req)) {
		return http_redirect(req, "/login", NULL);
	}

	fd = open("static/homepage.html", O_RDONLY);
	filesize = lseek(fd, 0, SEEK_END);

	dprintf(req->clientfd, "HTTP/1.0 200 OK\r\n");
	dprintf(req->clientfd, "Content-Type: text/html\r\n");
	dprintf(req->clientfd, "Content-Length: %ld\r\n", filesize);
	dprintf(req->clientfd, "\r\n");

	lseek(fd, 0, SEEK_SET);

	sendfile(req->clientfd, fd, NULL, filesize);
	close(fd);

	close(req->clientfd);

	freerequest(req);
	return NULL;
}

// does nothing but redirect to login actually
void *logout_handler(void *arg) {
	struct request *req = arg;

	return http_redirect(req, "/login/", NULL);
}

// checking the credentials of a login failed
void *loginfail_handler(void *arg) {
	struct request *req = arg;

	int fd = open("static/invalidlogin.html", O_RDONLY);

	off_t filesize = lseek(fd, 0, SEEK_END);

	dprintf(req->clientfd, "HTTP/1.0 200 OK\r\n");
	dprintf(req->clientfd, "Content-Type: text/html\r\n");
	dprintf(req->clientfd, "Content-Length: %ld\r\n", filesize);
	dprintf(req->clientfd, "\r\n");

	lseek(fd, 0, SEEK_SET);

	sendfile(req->clientfd, fd, NULL, filesize);

	close(fd);
	close(req->clientfd);

	freerequest(req);

	return NULL;
}

// displays the users profile
void *user_detail_view(void *arg) {
	struct request *req = arg;

	if (!logged_in(req)) {
		return http_redirect(req, "/login/", NULL);
	}

	// accept type in the request
	char *accept_type = get_header_value(req->reqh->hdrs, "Accept");

	// send json by default
	if (!accept_type || strstr(accept_type, "application/json")) {
		int len = 0;

		struct user *u = get_user(req->params[0]);

		char *json = serialize_user(u);

		free(u);

		len = strlen(json);

		dprintf(req->clientfd, "HTTP/1.0 200 OK\r\n");
		dprintf(req->clientfd, "Content-Type: application/json\r\n");
		dprintf(req->clientfd, "Content-Length: %d\r\n", len);
		dprintf(req->clientfd, "\r\n");

		dprintf(req->clientfd, "%s", json);

		free(json);
	}
	else {
		// send the html page which has javascript which requests json and fills the page
		int fd = open("static/calendar/userdetail.html", O_RDONLY);
		off_t filesize = lseek(fd, 0, SEEK_END);

		dprintf(req->clientfd, "HTTP/1.0 200 OK\r\n");
		dprintf(req->clientfd, "Content-Type: text/html\r\n");
		dprintf(req->clientfd, "Content-Length: %ld\r\n", filesize);
		dprintf(req->clientfd, "\r\n");

		lseek(fd, 0, SEEK_SET);

		sendfile(req->clientfd, fd, NULL, filesize);

		close(fd);
	}

	close(req->clientfd);

	freerequest(req);

	return NULL;
}

// take a user from the post data and update that user's appointments
void *user_update_view(void *arg) {
	int user_id;
	struct request *req = arg;

	if (!(user_id = logged_in(req))) {
		return http_redirect(req, "/login/", NULL);
	}

	if (!strcmp(req->reqh->action, "POST")) {
		struct user *u = get_user_from_request(req);

		// the user in the db
		struct user *local = get_user(u->id);

		// the updates to appointments
		strcpy(local->last_updated, u->last_updated);
		for (int i = 0; i < 182; i++) {
			local->appointments[i] = u->appointments[i];
		}
		// update the user
		update_user(local);
		free(local);
		free(u);

		dprintf(req->clientfd, "HTTP/1.0 200 OK\r\n");
		dprintf(req->clientfd, "Content-Length: 0\r\n");
		dprintf(req->clientfd, "\r\n");
	}

	close(req->clientfd);
	freerequest(req);

	return NULL;
}

// returns the json of the serialized current user to the browser
void *current_user_view(void *arg) {
	int user_id;
	struct request *req = arg;

	if (!(user_id = logged_in(req))) {
		return http_redirect(req, "/login/", NULL);
	}

	struct user *u = get_user(user_id);

	char *json = serialize_user(u);

	dprintf(req->clientfd, "HTTP/1.0 200 OK\r\n");
	dprintf(req->clientfd, "Content-Length: %ld\r\n", strlen(json));
	dprintf(req->clientfd, "Content-Type: application/json\r\n");
	dprintf(req->clientfd, "\r\n");

	dprintf(req->clientfd, "%s", json);

	free(json);
	free(u);
	close(req->clientfd);
	freerequest(req);

	return NULL;
}

// view all appointments
void *appointment_list_view(void *arg) {
	int user_id;
	struct request *req = arg;

	if (!(user_id = logged_in(req))) {
		return http_redirect(req, "/login/", NULL);
	}

	char *accept_type = get_header_value(req->reqh->hdrs, "Accept");

	// send json
	if (!accept_type || strstr(accept_type, "application/json")) {
		int len = 0;
		struct user *u = get_user(user_id);
		char *json = serialize_user(u);

		free(u);

		len = strlen(json);

		dprintf(req->clientfd, "HTTP/1.0 200 OK\r\n");
		dprintf(req->clientfd, "Content-Type: application/json\r\n");
		dprintf(req->clientfd, "Content-Length: %d\r\n", len);
		dprintf(req->clientfd, "\r\n");

		dprintf(req->clientfd, "%s", json);

		free(json);
	}
	else {
		// send html page template and javascript in it
		int fd = open("static/calendar/appointmentlist.html", O_RDONLY);
		off_t filesize = lseek(fd, 0, SEEK_END);

		dprintf(req->clientfd, "HTTP/1.0 200 OK\r\n");
		dprintf(req->clientfd, "Content-Type: text/html\r\n");
		dprintf(req->clientfd, "Content-Length: %ld\r\n", filesize);
		dprintf(req->clientfd, "\r\n");

		lseek(fd, 0, SEEK_SET);

		sendfile(req->clientfd, fd, NULL, filesize);

		close(fd);
	}

	close(req->clientfd);

	freerequest(req);

	return NULL;
}

// displays the users in that particular category, roles are hardcoded in html
void *serviceman_list_view(void *arg) {
	int role;
	struct request *req = arg;

	if (!logged_in(req)) {
		return http_redirect(req, "/login/", NULL);
	}

	switch (req->params[0]) {
		case 1:
			role = POLICE;
			break;
		case 2:
			role = DOCTOR;
			break;
		case 3:
			role = ENGINEER;
			break;
		case 4:
			role = TEACHER;
			break;
		case 5:
			role = LAWYER;
			break;
		case 6:
			role = ARTIST;
			break;
		case 7:
			role = SCIENTIST;
			break;
		case 8:
			role = MUSICIAN;
			break;
		case 9:
			role = BANKER;
			break;
		case 10:
			role = ELECTRICIAN;
			break;
		default:
			// invaid role
			return http404(req);
	}

	char *accept_type = get_header_value(req->reqh->hdrs, "Accept");

	// if there's no accept type, or others send json.
	if (!accept_type || strstr(accept_type, "application/json")) {
		int len = 0;
		struct user **users = get_all_users(role, &len);
		char *array = serialize_user_array(users, len);

		char *json = NULL;

		asprintf(&json, "{\"users\": %s}", array);
		
		free(array);

		for (int i = 0; i < len; i++) {
			free(users[i]);
		}
		free(users);

		len = strlen(json);

		dprintf(req->clientfd, "HTTP/1.0 200 OK\r\n");
		dprintf(req->clientfd, "Content-Type: application/json\r\n");
		dprintf(req->clientfd, "Content-Length: %d\r\n", len);
		dprintf(req->clientfd, "\r\n");

		dprintf(req->clientfd, "%s", json);

		free(json);
	}
	else {
		int fd = open("static/calendar/categorydetail.html", O_RDONLY);
		off_t filesize = lseek(fd, 0, SEEK_END);

		dprintf(req->clientfd, "HTTP/1.0 200 OK\r\n");
		dprintf(req->clientfd, "Content-Type: text/html\r\n");
		dprintf(req->clientfd, "Content-Length: %ld\r\n", filesize);
		dprintf(req->clientfd, "\r\n");

		lseek(fd, 0, SEEK_SET);

		sendfile(req->clientfd, fd, NULL, filesize);

		close(fd);
	}

	close(req->clientfd);

	freerequest(req);

	return NULL;
}

// calendar store entry point, static html
void *serviceman_category_view(void *arg) {
	struct request *req = arg;

	if (!logged_in(req)) {
		return http_redirect(req, "/login", NULL);
	}

	int fd = open("static/calendar/categories.html", O_RDONLY);
	off_t filesize = lseek(fd, 0, SEEK_END);

	dprintf(req->clientfd, "HTTP/1.0 200 OK\r\n");
	dprintf(req->clientfd, "Content-Type: text/html\r\n");
	dprintf(req->clientfd, "Content-Length: %ld\r\n", filesize);
	dprintf(req->clientfd, "\r\n");

	lseek(fd, 0, SEEK_SET);

	sendfile(req->clientfd, fd, NULL, filesize);

	close(fd);
	close(req->clientfd);

	freerequest(req);

}

// displays login page in GET, autenticates user in POST
void *login_page_handler(void *arg) {
	struct request *req = arg;

	if (!strcmp(req->reqh->action, "GET")) {
		int fd = open("static/login.html", O_RDONLY);
		off_t filesize = lseek(fd, 0, SEEK_END);
		dprintf(req->clientfd, "HTTP/1.0 200 OK\r\n");
		dprintf(req->clientfd, "Content-Type: text/html\r\n");
		dprintf(req->clientfd, "Content-Length: %ld\r\n", filesize);
		dprintf(req->clientfd, "\r\n");

		lseek(fd, 0, SEEK_SET);

		sendfile(req->clientfd, fd, NULL, filesize);
		close(fd);

	}
	else if (!strcmp(req->reqh->action, "POST")) {
		char *contype = get_header_value(req->reqh->hdrs, "Content-Type");
		if (!contype || strcmp(contype, "application/x-www-form-urlencoded")) {
			fprintf(stderr, "signup: post, no content type\n");
			return http415(req);
		}

		struct header *post_data = get_post_data(req->clientfd);

		char *username = get_header(post_data, "username");
		char *password = get_header(post_data, "password");

		if (!username || !password) {
			return http_redirect(req, "/loginfail", NULL);
		}

		if (authenticate(username, password)) {
			fprintf(stdout, "login_page_handler: %s just logged in\n", username);

			char *cookie = NULL;
			asprintf(&cookie, "Set-Cookie: logincreds=username=%s&password=%s", username, password);

			free(username);
			free(password);
			return http_redirect(req, "/", cookie);
		}
		else {
			free(username);
			free(password);
			return http_redirect(req, "/loginfail", NULL);
		}
	}

	close(req->clientfd);
	freerequest(req);	

	return NULL;
}

// delete a reply of a message
void *reply_delete_view(void *arg) {
	int user_id;
	struct request *req = arg;

	if (!(user_id = logged_in(req))) {
		return http_redirect(req, "/login", NULL);
	}

	// the parameters extracted from the url
	int category_id = req->params[0], msg_id = req->params[1], reply_id = req->params[2];

	// if delete successful, refresh the page
	if (delete_reply(category_id, msg_id, reply_id, user_id)) {
		char *redirect_url = NULL;

		asprintf(&redirect_url, "/messages/categories/%d/detail/", category_id);

		http_redirect(req, redirect_url, NULL);
		free(redirect_url);
		return NULL;
	}
	// invalid access
	else {
		dprintf(req->clientfd, "HTTP/1.0 403 Forbidden\r\n");
		dprintf(req->clientfd, "Content-Type: text/html\r\n");
		dprintf(req->clientfd, "\r\n");
		dprintf(req->clientfd, "<html><body><h1>Forbidden</h1></body></html>");
	}

	close(req->clientfd);
	freerequest(req);
	return NULL;

}

// create a new reply based on post data
void *reply_create_view(void *arg) {
	int user_id;
	struct request *req = arg;

	if (!(user_id = logged_in(req))) {
		return http_redirect(req, "/login", NULL);
	}

	if (!strcmp(req->reqh->action, "POST")) {
		struct header *post_data = get_post_data(req->clientfd);
		// variable in post data
		char *reply = get_header(post_data, "reply");

		struct reply *rply = new_reply(reply, user_id);

		freeheader(post_data);
		free(reply);

		// refresh the page if successful
		if (add_reply(rply, req->params[0], req->params[1])) {
			char *url = NULL;
			asprintf(&url, "/messages/categories/%d/detail/", req->params[0]);
			char u[strlen(url) + 1];
			strcpy(u, url);
			free(url);
			return http_redirect(req, u, NULL);
		}
		else {
			free(reply);
			return http507(req);
		}
	}

	close(req->clientfd);
	freerequest(req);

	return NULL;
}

// get all request of a particular message in a category, represented in json
void *reply_list_view(void *arg) {
	int user_id;

	struct request *req = arg;

	if (!(user_id = logged_in(req))) {
		return http_redirect(req, "/login", NULL);
	}

	// extract category, message ids from url
	int category_id = req->params[0];
	int msg_id = req->params[1];
	int len = 0;

	struct reply **replies = get_all_replies(category_id, msg_id, &len);

	char *json_array = serialize_reply_array(replies, len);
	char *json = NULL;

	asprintf(&json, "{\"replies\": %s}", json_array);

	len = strlen(json);

	dprintf(req->clientfd, "HTTP/1.0 200 OK\r\n");
	dprintf(req->clientfd, "Content-Type: application/json\r\n");
	dprintf(req->clientfd, "Content-Length: %d\r\n", len);
	dprintf(req->clientfd, "\r\n");

	dprintf(req->clientfd, "%s", json);

	free(json);
	free(json_array);

	close(req->clientfd);
	freerequest(req);

	return NULL;

}

// create a new category
void *category_create_view(void *arg) {
	int id;
	struct request *req = arg;

	if (!(id = logged_in(req))) {
		return http_redirect(req, "/login", NULL);
	}

	// if the requeste is post, extract data
	if (!strcmp(req->reqh->action, "POST")) {
		struct header *post_data = get_post_data(req->clientfd);

		// name of category
		char *category_name = get_header(post_data, "name");
		// description
		char *description = get_header(post_data, "description");

		if (!category_name || !description) {
			return http400(req);
		}

		struct category *c = new_category(category_name, description, id);
		// refresh page if successful
		if (id = add_category(c)) {
			fprintf(stdout, "category_create_view: new category %d created\n", id);
			free(c);
			return http_redirect(req, "/messages/categories/all/", NULL);
		}
		// out of memory in the db file
		else {
			fprintf(stdout, "category_create_view: add_category failed\n");
			free(c);
			return http507(req);
		}

	}

	close(req->clientfd);
	freerequest(req);
	return NULL;
}

// view message lists follows the same pattern as reply_list_view
void *message_list_view(void *arg) {
	int user_id;

	struct request *req = arg;

	if (!(user_id = logged_in(req))) {
		return http_redirect(req, "/login", NULL);
	}

	int category_id = req->params[0];
	int len = 0;

	struct message **messages = get_all_messages(category_id, &len);

	char *json_array = serialize_message_array(messages, len);
	char *json = NULL;

	asprintf(&json, "{\"messages\": %s}", json_array);

	len = strlen(json);

	dprintf(req->clientfd, "HTTP/1.0 200 OK\r\n");
	dprintf(req->clientfd, "Content-Type: application/json\r\n");
	dprintf(req->clientfd, "Content-Length: %d\r\n", len);
	dprintf(req->clientfd, "\r\n");

	dprintf(req->clientfd, "%s", json);

	free(json);
	free(json_array);

	close(req->clientfd);
	freerequest(req);

	return NULL;

}

// delete a message
void *message_delete_view(void *arg) {
	int user_id;
	struct request *req = arg;

	if (!(user_id = logged_in(req))) {
		return http_redirect(req, "/login", NULL);
	}

	// extract category_id and msg_id from url
	int category_id = req->params[0], msg_id = req->params[1];

	// refresh the page if successful
	if (delete_message(category_id, msg_id, user_id)) {
		char *redirect_url = NULL;
		asprintf(&redirect_url, "/messages/categories/%d/detail/", category_id);
		http_redirect(req, redirect_url, NULL);
		free(redirect_url);
		return NULL;
	}
	// error message not found
	else {
		dprintf(req->clientfd, "HTTP/1.0 403 Forbidden\r\n");
		dprintf(req->clientfd, "\r\n");
	}

	close(req->clientfd);
	freerequest(req);
	return NULL;
}

// create a new message, the same format as reply_create_view
void *message_create_view(void *arg) {
	int user_id;
	struct request *req = arg;

	if (!(user_id = logged_in(req))) {
		return http_redirect(req, "/login", NULL);
	}

	if (!strcmp(req->reqh->action, "POST")) {
		struct header *post_data = get_post_data(req->clientfd);
		char *message = get_header(post_data, "message");

		struct message *msg = new_message(message, user_id);

		freeheader(post_data);
		free(message);

		if (add_message(msg, req->params[0])) {
			char *url = NULL;
			asprintf(&url, "/messages/categories/%d/detail/", req->params[0]);
			char u[strlen(url) + 1];
			strcpy(u, url);
			free(msg);
			free(url);
			char *accept_type = NULL;
			return http_redirect(req, u, NULL);
		}
		else {
			free(msg);
			return http507(req);
		}
	}

	close(req->clientfd);
	freerequest(req);

	return NULL;
}

// delete a category
void *category_delete_view(void *arg) {
	int user_id;
	struct request *req = arg;

	if (!(user_id = logged_in(req))) {
		return http_redirect(req, "/login", NULL);
	}

	// extract category id from url
	int category_id = req->params[0];

	if (delete_category(category_id, user_id)) {
		return http_redirect(req, "/messages/categories/all", NULL);
	}
	else {
		dprintf(req->clientfd, "HTTP/1.0 403 Forbidden\r\n");
		dprintf(req->clientfd, "Content-Type: text/html\r\n");
		dprintf(req->clientfd, "\r\n");
		dprintf(req->clientfd, "<html><body><h1>Forbidden</h1></body></html>");
	}

	close(req->clientfd);
	freerequest(req);
	return NULL;
}

// the main page of message store
void *category_detail_view(void *arg) {
	int id;
	struct request *req = arg;

	if (!(id = logged_in(req))) {
		return http_redirect(req, "/login", NULL);
	}

	char *accept_type = get_header_value(req->reqh->hdrs, "Accept");

	// send json by default
	if (!accept_type || strstr(accept_type, "application/json")) {
		// get the cateogory
		struct category *c = get_category(req->params[0]);
		int len;
		// get all its messages
		struct message **messages = get_all_messages(c->cat_id, &len);
		char *msgs = serialize_message_array(messages, len);
		char *json = serialize_category(c);
		char *final = NULL;

		asprintf(&final, "{\"category\": %s, \"messages\": %s}", json, msgs);

		for (int i = 0; i < len; i++) {
			free(messages[i]);
		}

		free(messages);

		len = strlen(final);
		dprintf(req->clientfd, "HTTP/1.0 200 OK\r\n");
		dprintf(req->clientfd, "Content-Type: application/json\r\n");
		dprintf(req->clientfd, "Content-Length: %d\r\n", len);
		dprintf(req->clientfd, "\r\n");
		dprintf(req->clientfd, "%s", final);

		free(final);
		free(json);
		free(c);
	}
	else {
		// send the html template
		int fd = open("static/messages/categorydetail.html", O_RDONLY);
		off_t filesize = lseek(fd, 0, SEEK_END);

		dprintf(req->clientfd, "HTTP/1.0 200 OK\r\n");
		dprintf(req->clientfd, "Content-Type: text/html\r\n");
		dprintf(req->clientfd, "Content-Length: %ld\r\n", filesize);
		dprintf(req->clientfd, "\r\n");

		lseek(fd, 0, SEEK_SET);

		sendfile(req->clientfd, fd, NULL, filesize);

		close(fd);
	}

	close(req->clientfd);
	freerequest(req);
	return NULL;
}

// follows the same pattern as message_list_view
void *category_list_view(void *arg) {
	struct request *req = arg;


	if (!logged_in(req)) {
		return http_redirect(req, "/login", NULL);
	}

	char *accept_type = get_header_value(req->reqh->hdrs, "Accept");

	// if there's no accept type, or others send json.
	if (!accept_type || strstr(accept_type, "application/json")) {
		int len = 0;
		struct category **categories = get_all_categories(&len);
		char *json = serialize_category_array(categories, len);

		for (int i = 0; i < len; i++) {
			free(categories[i]);
		}
		free(categories);

		len = strlen(json);

		dprintf(req->clientfd, "HTTP/1.0 200 OK\r\n");
		dprintf(req->clientfd, "Content-Type: application/json\r\n");
		dprintf(req->clientfd, "Content-Length: %d\r\n", len);
		dprintf(req->clientfd, "\r\n");
		dprintf(req->clientfd, "%s", json);

		free(json);
	}
	else {
		int fd = open("static/messages/category_list.html", O_RDONLY);
		off_t filesize = lseek(fd, 0, SEEK_END);

		dprintf(req->clientfd, "HTTP/1.0 200 OK\r\n");
		dprintf(req->clientfd, "Content-Type: text/html\r\n");
		dprintf(req->clientfd, "Content-Length: %ld\r\n", filesize);
		dprintf(req->clientfd, "\r\n");

		lseek(fd, 0, SEEK_SET);

		sendfile(req->clientfd, fd, NULL, filesize);

		close(fd);
	}

	close(req->clientfd);

	freerequest(req);

	return NULL;
}

// http 415
void *http415(void *arg) {
	struct request *req = arg;

	int fd = open("static/415.html", O_RDONLY);

	off_t filesize = lseek(fd, 0, SEEK_END);

	lseek(fd, 0, SEEK_SET);

	dprintf(req->clientfd, "HTTP/1.0 415 Unsupported Media Type\r\n");
	dprintf(req->clientfd, "Content-Type: text/html\r\n");
	dprintf(req->clientfd, "Content-Length: %ld\r\n", filesize);
	dprintf(req->clientfd, "\r\n");
	sendfile(req->clientfd, fd, NULL, filesize);

	close(fd);
	close(req->clientfd);
	freerequest(req);
	return NULL;
}

// redirect to new_url, additional headers is not null, add that header too in the response, must be dynamically allocated
void *http_redirect(struct request *req, char *new_url, char *additional_headers) {
	dprintf(req->clientfd, "HTTP/1.0 303 See Other\r\n");
	dprintf(req->clientfd, "Location: http://localhost:8000%s\r\n", new_url);
	// add headers like cookies
	if (additional_headers) {
		dprintf(req->clientfd, "%s\r\n", additional_headers);
	}
	dprintf(req->clientfd, "\r\n");

	free(additional_headers);
	close(req->clientfd);
	freerequest(req);
	return NULL;
}

void *http507(void *arg) {
	struct request *req = arg;
	dprintf(req->clientfd, "HTTP/1.0 507 Insufficient Storage\r\n");
	dprintf(req->clientfd, "\r\n");

	close(req->clientfd);
	freerequest(req);

	return NULL;
}

// signup page, follows the same pattern as login page handler
void *signup_page_handler(void *arg) {
	struct request *req = arg;

	if (!strcmp(req->reqh->action, "GET")) {
		int fd = open("static/signup.html", O_RDONLY);
		off_t filesize = lseek(fd, 0, SEEK_END);
		lseek(fd, 0, SEEK_SET);
		dprintf(req->clientfd, "HTTP/1.0 200 OK\r\n");
		dprintf(req->clientfd, "Content-Type: text/html\r\n");
		dprintf(req->clientfd, "Content-Length: %ld\r\n", filesize);
		dprintf(req->clientfd, "\r\n");
		sendfile(req->clientfd, fd, NULL, filesize);
		close(fd);

	}
	else if (!strcmp(req->reqh->action, "POST")) {
		char *contype = get_header_value(req->reqh->hdrs, "Content-Type");

		// unknown encoding in the form
		if (!contype || strcmp(contype, "application/x-www-form-urlencoded")) {
			fprintf(stderr, "signup: post, no content type\n");
			return http415(req);
		}

		// get post data
		struct header *post_data = get_post_data(req->clientfd);

		if (!post_data) {
			free(contype);
			return http415(req);
		}

		char *username = get_header(post_data, "username"), *cookie = NULL;
		char *password = get_header(post_data, "password");
		char *date = get_header(post_data, "date");

		int roles = get_roles(post_data);

		freeheader(post_data);

		struct user *u = create_new_user(username, password, roles, date);

		free(username);
		free(password);
		free(date);

		int id;
		// redirect to home page, set cookie with username and password
		if (id = add_user(u)) {
			fprintf(stdout, "new user create with id - %d, name - %s\n", id, u->username);

			asprintf(&cookie, "Set-Cookie: logincreds=username=%s&password=%s", u->username, u->password);

			free(u);
			return http_redirect(req, "/", cookie);
		}
		// no more space in the user store
		else {
			free(u);
			return http507(req);
		}
	}
	close(req->clientfd);
	freerequest(req);
	return NULL;
}

// upload files
void *files_upload_view(void *arg) {
	int user_id;
	struct request *req = arg;

	if (!(user_id = logged_in(req))) {
		return http_redirect(req, "/login", NULL);
	}

	if (!strcmp(req->reqh->action, "GET")) {
		int fd = open("static/files/fileupload.html", O_RDONLY);

		off_t filesize = lseek(fd, 0, SEEK_END);

		dprintf(req->clientfd, "HTTP/1.0 200 OK\r\n");
		dprintf(req->clientfd, "Content-Type: text/html\r\n");
		dprintf(req->clientfd, "Content-Length: %ld\r\n", filesize);
		dprintf(req->clientfd, "\r\n");

		lseek(fd, 0, SEEK_SET);

		sendfile(req->clientfd, fd, NULL, filesize);
		close(fd);
	}
	else if (!strcmp(req->reqh->action, "POST")){
		char *filedata = NULL;
		// get the file data
		ssize_t filesize = get_multipart_data(req, &filedata);
		char *filename = get_header_value(req->reqh->hdrs, "filename");
		// add file to store
		if (add_file(filedata, filesize, filename, user_id)) {
			free(filedata);
			return http_redirect(req, "/files/all", NULL);
		}
		else {
			free(filedata);
			return http507(req);
		}
	}
	close(req->clientfd);
	freerequest(req);

	return NULL;
}

// delete a file in the file store
void *files_delete_view(void *arg) {
	int user_id;
	struct request *req = arg;

	if (!(user_id = logged_in(req))) {
		return http_redirect(req, "/login", NULL);
	}

	int file_id = req->params[0];

	return delete_file(user_id, file_id) ?
		http_redirect(req, "/files/all", NULL) :
		http404(req);
}

void *files_download_view(void *arg) {
	int user_id;
	struct request *req = arg;

	if (!(user_id = logged_in(req))) {
		return http_redirect(req, "/login", NULL);
	}

	char *filedata = NULL, *filename = NULL;
	ssize_t filesize = get_file(user_id, req->params[0], &filedata, &filename);

	if (filedata) {
		dprintf(req->clientfd, "HTTP/1.0 200 OK\r\n");
		dprintf(req->clientfd, "Content-Length: %ld\r\n", filesize);
		dprintf(req->clientfd, "Content-Type: application/octet\r\n");
		dprintf(req->clientfd, "Content-Disposition: attachment; filename=\"%s\"\r\n", filename);
		dprintf(req->clientfd, "\r\n");
		send(req->clientfd, filedata, filesize, 0);

		free(filedata);
		free(filename);
	}
	else {
		free(filename);
		return http404(req);
	}

	close(req->clientfd);
	freerequest(req);

	return NULL;
}

// same pattern as reply_list_view
void *files_list_view(void *arg) {
	int user_id;
	struct request *req = arg;

	if (!(user_id = logged_in(req))) {
		return http_redirect(req, "/login", NULL);
	}

	char *accept_type = get_header_value(req->reqh->hdrs, "Accept");

	if (!accept_type || strstr(accept_type, "application/json")) {
		int len = 0;

		struct filehead **fheads = get_all_files(user_id, &len);
		
		char *array = serialize_file_array(fheads, len);

		char *json = NULL;

		asprintf(&json, "{\"files\": %s}", array);

		free(array);

		dprintf(req->clientfd, "HTTP/1.0 200 OK\r\n");
		dprintf(req->clientfd, "Content-Type: application/json\r\n");
		dprintf(req->clientfd, "Content-Length: %ld\r\n", strlen(json));
		dprintf(req->clientfd, "\r\n");

		dprintf(req->clientfd, "%s\r\n", json);

		free(json);
	}
	else {
		int fd = open("static/files/filelist.html", O_RDONLY);

		off_t filesize = lseek(fd, 0, SEEK_END);

		dprintf(req->clientfd, "HTTP/1.0 200 OK\r\n");
		dprintf(req->clientfd, "Content-Type: text/html\r\n");
		dprintf(req->clientfd, "Content-Length: %ld\r\n", filesize);
		dprintf(req->clientfd, "\r\n");
	
		lseek(fd, 0, SEEK_SET);

		sendfile(req->clientfd, fd, NULL, filesize);
	}

	close(req->clientfd);
	freerequest(req);

	return NULL;
}

void set_block_full(char *bitvector, int block_number) {
	bitvector[block_number / 8] |= (1 << (block_number % 8));
	return;
}

int is_block_free(char *bitvector, int block_number) {
	return (bitvector[block_number / 8] & (1 << (block_number % 8))) == 0;
}

void set_block_empty(char *bitvector, int block_number) {
	bitvector[block_number / 8] &= ~(1 << (block_number % 8));
	return;
}

struct user *create_new_user(char *username, char *password, int roles, char *date) {
	struct user *u = calloc(1, sizeof(*u));
	u->roles = roles;
	strcpy(u->last_updated, date);
	strcpy(u->username, username);
	strcpy(u->password, password);
	return u;
}

// adds a new user
int add_user(struct user *new_user) {
	int fd = open(USER_FILE, O_RDWR), block;
	struct usermeta mu;

	struct flock lock = {
		.l_type = F_WRLCK,
		.l_whence = SEEK_SET,
		.l_start = 0,
		.l_len = USER_BV_SIZE + USER_BLOCK_SIZE, /* the bit vector and the metadata */
		.l_pid = 0,		/* required to be 0 */
	};

	fcntl(fd, F_OFD_SETLKW, &lock);

	char *block_status = malloc(USER_BV_SIZE);

	read(fd, block_status, sizeof(block_status));

	read(fd, &mu, sizeof(mu));

	// exclude bitvector blocks and user meta blocks from checking.
	for (block = USER_BV_SIZE / USER_BLOCK_SIZE + 1; block < USER_BLOCKS_TOTAL; block++) {
		if (!is_block_free(block_status, block)) {
			continue;
		}
		set_block_full(block_status, block);
		break;
	}

	if (block == USER_BLOCKS_TOTAL) {
		free(block_status);
		close(fd);
		return 0;
	}

	new_user->id = ++mu.id;
	// write changes to file
	lseek(fd, block * USER_BLOCK_SIZE, SEEK_SET);
	write(fd, new_user, sizeof(*new_user));

	// update the block status
	lseek(fd, 0, SEEK_SET);
	write(fd, block_status, sizeof(block_status));

	// change the status
	write(fd, &mu, sizeof(mu));

	fdatasync(fd);

	// unlock the lock
	lock.l_type = F_UNLCK;

	fcntl(fd, F_OFD_SETLKW, &lock);

	close(fd);

	free(block_status);

	return new_user->id;
}

struct user **get_all_users(int role, int *len) {
	int fd = open(USER_FILE, O_RDONLY), block;

	struct flock lock = {
		.l_type = F_RDLCK,
		.l_whence = SEEK_SET,
		.l_start = 0,
		.l_len = USER_BV_SIZE,
		.l_pid = 0,
	};

	fcntl(fd, F_OFD_SETLKW, &lock);

	struct user *u = malloc(sizeof(*u));

	char *block_status = malloc(USER_BV_SIZE);

	read(fd, block_status, sizeof(block_status));

	int size = 20, i = 0;
	struct user **users = malloc(sizeof(*users) * size);

	for (block = USER_BV_SIZE / USER_BLOCK_SIZE + 1; block < USER_BLOCKS_TOTAL; block++) {
		if (is_block_free(block_status, block)) {
			continue;
		}

		struct flock u_lock = {
			.l_type = F_RDLCK,
			.l_whence = SEEK_SET,
			.l_len = USER_BLOCK_SIZE,
			.l_start = block * USER_BLOCK_SIZE,
			.l_pid = 0,
		};
		struct user u;

		fcntl(fd, F_OFD_SETLKW, &u_lock);
		lseek(fd, block * USER_BLOCK_SIZE, SEEK_SET);

		read(fd, &u, sizeof(u));
	
		if (u.roles & role) {
			users[i] = malloc(sizeof(**users));
			*users[i] = u;
			i++;
			if (i == size) {
				size += 20;
				users = realloc(users, sizeof(*users) * size);
			}
		}

		u_lock.l_type = F_UNLCK;
		fcntl(fd, F_OFD_SETLKW, &u_lock);


	}

	users = realloc(users, sizeof(*users) * i);

	free(block_status);
	close(fd);

	*len = i;

	return users;
}

char *serialize_user_array(struct user **categories, int len) {
	char *prev = malloc(1);
	prev[0] = 0;
	for (int i = 0; i < len; i++) {
		char *temp = serialize_user(categories[i]);
		char *t = NULL;

		asprintf(&t, i == 0 ? "%s%s" : "%s, %s", prev, temp);

		free(prev);
		free(temp);

		prev = t;
	}

	char *array = NULL;

	asprintf(&array, "[%s]", prev);
	free(prev);

	return array;
}

char *serialize_user(struct user *u) {
	char *str = NULL;

	asprintf(&str, "\"id\": %d, \"username\": \"%s\"", u->id, u->username);

	char *prev = malloc(1);
	prev[0] = 0;
	for (int i = 0; i < 182; i++) {
		char *temp = NULL;
		asprintf(&temp, i == 0 ? "%s%d" : "%s, %d", prev, u->appointments[i]);
		free(prev);
		prev = temp;
	}
	char *temp = NULL;
	asprintf(&temp, "\"appointments\": [%s], \"current\": %d, \"last_updated\": \"%s\"", prev, u->top_app, u->last_updated);
	char *json = NULL;

	asprintf(&json, "{%s, %s}", str, temp);

	free(temp);
	free(str);

	return json;
}

// search for a user in the user store and update the data
void update_user(struct user *u) {
	int fd = open(USER_FILE, O_RDWR), block;
	struct usermeta mu;

	struct flock lock = {
		.l_type = F_WRLCK,
		.l_whence = SEEK_SET,
		.l_start = 0,
		.l_len = USER_BV_SIZE,
		.l_pid = 0,
	};

	fcntl(fd, F_OFD_SETLKW, &lock);

	char *block_status = malloc(USER_BV_SIZE);
	struct user cur;

	read(fd, block_status, sizeof(block_status));

	for (block = USER_BV_SIZE / USER_BLOCK_SIZE + 1; block < USER_BLOCKS_TOTAL; block++) {
		if (is_block_free(block_status, block)) {
			continue;
		}

		struct flock u_lock = {
			.l_type = F_WRLCK,
			.l_whence = SEEK_SET,
			.l_len = USER_BLOCK_SIZE,
			.l_start = block * USER_BLOCK_SIZE,
			.l_pid = 0,
		};

		fcntl(fd, F_OFD_SETLKW, &u_lock);
		lseek(fd, block * USER_BLOCK_SIZE, SEEK_SET);

		read(fd, &cur, sizeof(cur));

		// user will always be found
		if (u->id == cur.id) {
			lseek(fd, block * USER_BLOCK_SIZE, SEEK_SET);
			write(fd, u, sizeof(*u));
			free(block_status);
			close(fd);
			return;
		}
		u_lock.l_type = F_UNLCK;
		fcntl(fd, F_OFD_SETLKW, &u_lock);
	}
}

// get a user structure from the user store based on id
struct user *get_user(int id) {
	int fd = open(USER_FILE, O_RDONLY), block;
	struct usermeta mu;

	struct flock lock = {
		.l_type = F_RDLCK,
		.l_whence = SEEK_SET,
		.l_start = 0,
		.l_len = USER_BV_SIZE + USER_BLOCK_SIZE,
		.l_pid = 0,
	};

	fcntl(fd, F_OFD_SETLKW, &lock);

	struct user *u = malloc(sizeof(*u));

	char *block_status = malloc(USER_BV_SIZE);

	read(fd, block_status, sizeof(block_status));

	read(fd, &mu, sizeof(mu));

	for (block = USER_BV_SIZE / USER_BLOCK_SIZE + 1; block < USER_BLOCKS_TOTAL; block++) {
		if (is_block_free(block_status, block)) {
			continue;
		}

		struct flock u_lock = {
			.l_type = F_RDLCK,
			.l_whence = SEEK_SET,
			.l_len = USER_BLOCK_SIZE,
			.l_start = block * USER_BLOCK_SIZE,
			.l_pid = 0,
		};

		fcntl(fd, F_OFD_SETLKW, &u_lock);
		lseek(fd, block * USER_BLOCK_SIZE, SEEK_SET);

		read(fd, u, sizeof(*u));

		if (u->id == id) {
			free(block_status);
			close(fd);
			return u;
		}
		u_lock.l_type = F_UNLCK;
		fcntl(fd, F_OFD_SETLKW, &u_lock);
	}

	free(u);
	free(block_status);
	close(fd);

	return NULL;
}

// create files if they don't already exist
void create_files(char *filename, ssize_t filesize) {
	FILE *fp = fopen(FL_FILE, "r");
	
	if (!fp) {
		fp = fopen(FL_FILE, "w");
		for (ssize_t i = 0; i < filesize; i++) {
			fputc(0, fp);
		}
		fclose(fp);
	}
}

void initialize_bit_vector(char *filename, int total_blocks, int filled_blocks) {
	int updated = 0;
	int fd = open(filename, O_RDWR);

	// size of bitvector is total_blocks / 8
	char *bitvector = malloc(total_blocks / 8);

	read(fd, bitvector, total_blocks / 8);

	// check for unfilled blocks in filled block region
	for (int block = 0; block < filled_blocks; block++) {
		if (is_block_free(bitvector, block)) {
			set_block_full(bitvector, block);
			updated = 1;
		}
	}

	// if data is updated, write it back to the file
	if (updated) {
		fprintf(stdout, "initialize_bit_vector: initalized %d blocks\n", filled_blocks);
		lseek(fd, 0, SEEK_SET);
		write(fd, bitvector, total_blocks / 8);
		fdatasync(fd);
	}

	close(fd);

	free(bitvector);
}

// authenticate a user by validating username and password from the user store.
int authenticate(char *username, char *password) {
	int fd, rv, block;
	struct user u;
	fd = open(USER_FILE, O_RDONLY);

	struct flock lock = {
		.l_type = F_RDLCK,
		.l_whence = SEEK_SET,
		.l_start = 0,
		.l_len = USER_BV_SIZE,			/* the bit vector */
		.l_pid = 0,				/* required to be 0 */
	};

	char *block_status = malloc(USER_BV_SIZE);

	rv = fcntl(fd, F_OFD_SETLKW, &lock);

	if (rv == -1) {
		fprintf(stderr, "logged_in: cannot acquire lock\n");
		return 0;
	}

	read(fd, block_status, USER_BV_SIZE);

	for (block = USER_BV_SIZE / USER_BLOCK_SIZE + 1; block < USER_BLOCKS_TOTAL; block++) {
		if (is_block_free(block_status, block)) {
		}

		struct flock block_lock = {
			.l_type = F_RDLCK,
			.l_whence = SEEK_SET,
			.l_len = USER_BLOCK_SIZE,
			.l_start = block * USER_BLOCK_SIZE,
			.l_pid = 0,
		};

		fcntl(fd, F_OFD_SETLKW, &block_lock);
		lseek(fd, block * USER_BLOCK_SIZE, SEEK_SET);
		read(fd, &u, sizeof(u));

		if (!strcmp(u.username, username) && !strcmp(u.password, password)) {
			close(fd);				// all locks released here in case of success
			return u.id;
		}

		block_lock.l_type = F_UNLCK;

		fcntl(fd, F_OFD_SETLKW, &block_lock);		// free that block

	}

	lock.l_type = F_UNLCK;

	fcntl(fd, F_OFD_SETLKW, lock);

	close(fd);

	return 0;
}

// get the current logged in user's id
int logged_in(struct request *req) {
	struct header *cookie = get_cookie_data(req);

	if (!cookie) {
		return 0;
	}

	char *username = get_header(cookie, "username");
	char *password = get_header(cookie, "password");

	freeheader(cookie);

	if (!username || !password) {
		return 0;
	}

	int id = authenticate(username, password);

	free(username);
	free(password);

	return id;
}

struct category *new_category(char *name, char *description, int owner_id) {
	struct category *new_category = calloc(1, sizeof(*new_category));
	strcpy(new_category->name, name);
	strcpy(new_category->description, description);
	new_category->owner_id = owner_id;
	return new_category;
}

int add_category(struct category *new_category) {
	int fd = open(MSG_FILE, O_RDWR);
	int block;
	struct messagemeta mm;

	struct flock lock = {
		.l_type = F_WRLCK,
		.l_whence = SEEK_SET,
		.l_start = 0,
		.l_len = MSG_BV_SIZE + MSG_BLOCK_SIZE,	/* bitvector and meta block */
		.l_pid = 0,
	};

	fcntl(fd, F_OFD_SETLKW, &lock);

	char *block_status = malloc(MSG_BV_SIZE);
	read(fd, block_status, MSG_BV_SIZE);

	read(fd, &mm, sizeof(mm));

	for (block = MSG_BV_SIZE / MSG_BLOCK_SIZE + 1; block < MSG_BLOCKS_TOTAL; block++) {
		if (!is_block_free(block_status, block)) {
			continue;
		}
		set_block_full(block_status, block);
		break;
	}

	if (block == MSG_BLOCKS_TOTAL) {
		free(block_status);
		close(fd);
		return 0;
	}

	new_category->cat_id = ++mm.category_count;
	new_category->next_category = mm.first_category;
	mm.first_category = block * MSG_BLOCK_SIZE;

	lseek(fd, block * MSG_BLOCK_SIZE, SEEK_SET);
	write(fd, new_category, sizeof(*new_category));

	lseek(fd, 0, SEEK_SET);
	write(fd, block_status, MSG_BV_SIZE);

	write(fd, &mm, sizeof(mm));

	fdatasync(fd);

	lock.l_type = F_UNLCK;
	fcntl(fd, F_OFD_SETLKW, &lock);

	return new_category->cat_id;
}

struct category *get_category(int category_id) {
	int fd = open(MSG_FILE, O_RDONLY);
	struct messagemeta mm;

	struct flock lock = {
		.l_start = MSG_BV_SIZE,
		.l_whence = SEEK_SET,
		.l_type = F_RDLCK,
		.l_len = MSG_BLOCK_SIZE,
		.l_pid = 0,
	};

	fcntl(fd, F_OFD_SETLKW, &lock);

	lseek(fd, MSG_BV_SIZE, SEEK_SET);

	read(fd, &mm, sizeof(mm));

	lock.l_type = F_UNLCK;

	fcntl(fd, F_OFD_SETLKW, &lock);

	struct category *c = malloc(sizeof(*c));

	off_t next = mm.first_category;

	while (next) {
		lock.l_start = next;
		fcntl(fd, F_OFD_SETLKW, &lock);

		lseek(fd, next, SEEK_SET);

		read(fd, c, sizeof(*c));

		if (c->cat_id == category_id) {
			close(fd);
			return c;
		}

		lock.l_type = F_UNLCK;
		fcntl(fd, F_OFD_SETLKW, &lock);

		next = c->next_category;
	}

	free(c);
	close(fd);
	return NULL;
}

struct category **get_all_categories(int *len) {
	int fd = open(MSG_FILE, O_RDONLY);
	struct messagemeta mm;

	struct flock lock = {
		.l_start = MSG_BV_SIZE,
		.l_whence = SEEK_SET,
		.l_type = F_RDLCK,
		.l_len = MSG_BLOCK_SIZE,
		.l_pid = 0,
	};

	fcntl(fd, F_OFD_SETLKW, &lock);

	lseek(fd, MSG_BV_SIZE, SEEK_SET);

	read(fd, &mm, sizeof(mm));

	lock.l_type = F_UNLCK;

	fcntl(fd, F_OFD_SETLKW, &lock);

	int size = 20;
	struct category **categories = malloc(sizeof(*categories) * size);

	off_t next = mm.first_category;
	int i = 0;

	while (next) {
		lock.l_start = next;
		fcntl(fd, F_OFD_SETLKW, &lock);

		lseek(fd, next, SEEK_SET);

		struct category *c = calloc(1, sizeof(*c));

		read(fd, c, sizeof(*c));

		lock.l_type = F_UNLCK;
		fcntl(fd, F_OFD_SETLKW, &lock);

		if (i == size) {
			size += 20;
			categories = realloc(categories, sizeof(*categories) * size);
		}

		categories[i++] = c;

		next = c->next_category;
	}

	categories = realloc(categories, sizeof(*categories) * i);

	*len = i;

	close(fd);
	return categories;
}

char *serialize_category_array(struct category **categories, int len) {
	char *prev = malloc(1);
	prev[0] = 0;
	for (int i = 0; i < len; i++) {
		char *temp = serialize_category(categories[i]);
		char *t = NULL;

		asprintf(&t, i == 0 ? "%s%s" : "%s, %s", prev, temp);

		free(prev);
		free(temp);

		prev = t;
	}

	char *array = NULL;

	asprintf(&array, "{\"categories\": [%s], \"length\": %d}", prev, len);
	free(prev);

	return array;
}

char *serialize_category(struct category *category) {
	char *str = NULL;

	asprintf(&str, "{\"id\": %d, \"owner_id\": %d, \"name\": \"%s\", \"description\": \"%s\"}",
			category->cat_id, category->owner_id, category->name,
			category->description);
	return str;
}

struct message *new_message(char *content, int owner_id) {
	struct message *m = calloc(1, sizeof(*m));

	strcpy(m->content, content);
	m->owner_id = owner_id;

	return m;
}

int add_message(struct message *m, int category_id) {
	int fd = open(MSG_FILE, O_RDWR), block;
	struct messagemeta mm;

	struct flock lock = {
		.l_start = 0,
		.l_whence = SEEK_SET,
		.l_type = F_WRLCK,
		.l_len = MSG_BV_SIZE + MSG_BLOCK_SIZE,
		.l_pid = 0,
	};

	fcntl(fd, F_OFD_SETLKW, &lock);

	char *block_status = malloc(MSG_BV_SIZE);

	read(fd, block_status, MSG_BV_SIZE);

	lseek(fd, MSG_BV_SIZE, SEEK_SET);

	read(fd, &mm, sizeof(mm));

	for (block = MSG_BV_SIZE / MSG_BLOCK_SIZE + 1; block < MSG_BLOCKS_TOTAL; block++) {
		if (!is_block_free(block_status, block)) {
			continue;
		}
		set_block_full(block_status, block);
		break;
	}

	if (block == MSG_BLOCKS_TOTAL) {
		free(block_status);
		close(fd);
		return 0;
	}

	struct category *c = malloc(sizeof(*c));

	off_t next = mm.first_category;


	while (next) {
		lock.l_start = next;
		fcntl(fd, F_OFD_SETLKW, &lock);

		lseek(fd, next, SEEK_SET);

		read(fd, c, sizeof(*c));

		if (c->cat_id == category_id) {
			break;
		}

		lock.l_type = F_UNLCK;
		fcntl(fd, F_OFD_SETLKW, &lock);

		next = c->next_category;
	}

	if (!next) {
		close(fd);
		free(c);
		return 0;
	}

	off_t msg_location = c->first_message, prev = 0;
	struct message temp;

	while (msg_location) {
		struct flock msglock = {
			.l_whence = SEEK_SET,
			.l_len = MSG_BLOCK_SIZE,
			.l_start = msg_location,
			.l_pid = 0,
			.l_type = F_RDLCK,
		};

		fcntl(fd, F_OFD_SETLKW, &msglock);

		lseek(fd, msg_location, SEEK_SET);

		read(fd, &temp, sizeof(temp));

		msglock.l_type = F_UNLCK;

		fcntl(fd, F_OFD_SETLKW, &msglock);

		prev = msg_location;
		msg_location = temp.next_message;
	}
	lseek(fd, block * MSG_BLOCK_SIZE, SEEK_SET);
	m->msg_id = ++mm.messages_count;
	write(fd, m, sizeof(*m));

	if (!prev) {
		c->first_message = block * MSG_BLOCK_SIZE;
		lseek(fd, next, SEEK_SET);
		struct flock msglock = {
			.l_whence = SEEK_SET,
			.l_len = MSG_BLOCK_SIZE,
			.l_start = msg_location,
			.l_pid = 0,
			.l_type = F_WRLCK,
		};
		fcntl(fd, F_OFD_SETLKW, &msglock);

		lseek(fd, next, SEEK_SET);

		write(fd, c, sizeof(*c));

		msglock.l_type = F_UNLCK;

		fcntl(fd, F_OFD_SETLKW, &msglock);
	}
	else {
		struct flock msglock = {
			.l_whence = SEEK_SET,
			.l_len = MSG_BLOCK_SIZE,
			.l_start = prev,
			.l_pid = 0,
			.l_type = F_WRLCK,
		};
		fcntl(fd, F_OFD_SETLKW, &msglock);

		lseek(fd, prev, SEEK_SET);
		read(fd, &temp, sizeof(temp));
		temp.next_message = block * MSG_BLOCK_SIZE;

		lseek(fd, prev, SEEK_SET);
		write(fd, &temp, sizeof(temp));

		msglock.l_type = F_UNLCK;

		fcntl(fd, F_OFD_SETLKW, &msglock);
	}

	lseek(fd, 0, SEEK_SET);

	write(fd, block_status, MSG_BV_SIZE);

	write(fd, &mm, sizeof(mm));

	lock.l_start = 0;
	lock.l_len = MSG_BV_SIZE + MSG_BLOCK_SIZE;
	lock.l_type = F_UNLCK;

	fcntl(fd, F_OFD_SETLKW, &lock);

	close(fd);

	return m->msg_id;
}

struct message **get_all_messages(int category_id, int *len) {
	int fd = open(MSG_FILE, O_RDONLY);
	struct messagemeta mm;

	struct flock lock = {
		.l_start = MSG_BV_SIZE,
		.l_whence = SEEK_SET,
		.l_type = F_RDLCK,
		.l_len = MSG_BLOCK_SIZE,
		.l_pid = 0,
	};

	fcntl(fd, F_OFD_SETLKW, &lock);

	lseek(fd, MSG_BV_SIZE, SEEK_SET);

	read(fd, &mm, sizeof(mm));

	lock.l_type = F_UNLCK;

	fcntl(fd, F_OFD_SETLKW, &lock);

	struct category *c = malloc(sizeof(*c));

	off_t next = mm.first_category;

	while (next) {
		lock.l_start = next;
		fcntl(fd, F_OFD_SETLKW, &lock);

		lseek(fd, next, SEEK_SET);

		read(fd, c, sizeof(*c));

		if (c->cat_id == category_id) {
			break;
		}

		lock.l_type = F_UNLCK;
		fcntl(fd, F_OFD_SETLKW, &lock);

		next = c->next_category;
	}

	if (!next) {
		close(fd);
		free(c);
		return NULL;
	}

	int size = 20;
	struct message **messages = malloc(sizeof(*messages) * size);
	int i = 0;
	off_t msg_location = c->first_message;

	while (msg_location) {
		struct flock msglock = {
			.l_whence = SEEK_SET,
			.l_len = MSG_BLOCK_SIZE,
			.l_start = msg_location,
			.l_pid = 0,
			.l_type = F_RDLCK,
		};

		fcntl(fd, F_OFD_SETLKW, &msglock);

		lseek(fd, msg_location, SEEK_SET);

		messages[i] = malloc(sizeof(*messages[i]));

		read(fd, messages[i], sizeof(*messages[i]));

		msglock.l_type = F_UNLCK;

		fcntl(fd, F_OFD_SETLKW, &msglock);

		if (i == size) {
			size += 20;
			messages = realloc(messages, sizeof(*messages) * size);
		}

		msg_location = messages[i]->next_message;
		i++;
	}

	messages = realloc(messages, sizeof(*messages) * i);

	lock.l_type = F_UNLCK;

	fcntl(fd, F_OFD_SETLKW, &lock);

	*len = i;

	close(fd);

	return messages;
}

char *serialize_message_array(struct message **messages, int len) {
	char *prev = malloc(1);
	prev[0] = 0;
	for (int i = 0; i < len; i++) {
		char *temp = serialize_message(messages[i]);
		char *t = NULL;

		asprintf(&t, i == 0 ? "%s%s" : "%s, %s", prev, temp);

		free(prev);
		free(temp);

		prev = t;
	}

	char *array = NULL;

	asprintf(&array, "[%s]", prev);
	free(prev);

	return array;
}

char *serialize_message(struct message *message) {
	char *str = NULL;

	asprintf(&str, "{\"id\": %d, \"owner_id\": %d, \"content\": \"%s\"}",
			message->msg_id, message->owner_id,
			message->content);
	return str;
}

struct reply *new_reply(char *content, int owner_id) {
	struct reply *reply = calloc(1, sizeof(*reply));

	strcpy(reply->content, content);
	reply->owner_id = owner_id;
	return reply;
}

int add_reply(struct reply *reply, int category_id, int msg_id) {
	int fd = open(MSG_FILE, O_RDWR), block;
	struct messagemeta mm;

	struct flock lock = {
		.l_start = 0,
		.l_whence = SEEK_SET,
		.l_type = F_WRLCK,
		.l_len = MSG_BV_SIZE + MSG_BLOCK_SIZE,
		.l_pid = 0,
	};

	fcntl(fd, F_OFD_SETLKW, &lock);

	char *block_status = malloc(MSG_BV_SIZE);

	read(fd, block_status, MSG_BV_SIZE);

	lseek(fd, MSG_BV_SIZE, SEEK_SET);

	read(fd, &mm, sizeof(mm));

	printf("add_reply: reply_id = %d\n", mm.replies_count);
	for (block = MSG_BV_SIZE / MSG_BLOCK_SIZE + 1; block < MSG_BLOCKS_TOTAL; block++) {
		if (!is_block_free(block_status, block)) {
			continue;
		}
		set_block_full(block_status, block);
		break;
	}

	if (block == MSG_BLOCKS_TOTAL) {
		free(block_status);
		close(fd);
		return 0;
	}

	struct category c;

	off_t next = mm.first_category;

	while (next) {
		lock.l_start = next;
		fcntl(fd, F_OFD_SETLKW, &lock);

		lseek(fd, next, SEEK_SET);

		read(fd, &c, sizeof(c));

		if (c.cat_id == category_id) {
			break;
		}

		lock.l_type = F_UNLCK;
		fcntl(fd, F_OFD_SETLKW, &lock);

		next = c.next_category;
	}

	if (!next) {
		free(block_status);
		close(fd);
		return 0;
	}

	off_t msg_location = c.first_message, prev = 0;
	struct message msg;
	memset(&msg, 0, sizeof(msg));
	struct flock msglock = {
		.l_whence = SEEK_SET,
		.l_len = MSG_BLOCK_SIZE,
		.l_start = msg_location,
		.l_pid = 0,
		.l_type = F_WRLCK,
	};

	while (msg_location) {
		fcntl(fd, F_OFD_SETLKW, &msglock);

		lseek(fd, msg_location, SEEK_SET);

		read(fd, &msg, sizeof(msg));

		if (msg.msg_id == msg_id) {
			break;
		}
		msglock.l_type = F_UNLCK;

		fcntl(fd, F_OFD_SETLKW, &msglock);

		msg_location = msg.next_message;
	}

	if (!msg_location) {
		close(fd);
		return 0;
	}

	off_t reply_location = msg.first_reply;
	struct reply r;
	struct flock reply_lock = {
		.l_whence = SEEK_SET,
		.l_start = reply_location,
		.l_len = MSG_BLOCK_SIZE,
		.l_type = F_WRLCK,
		.l_pid = 0,
	};

	memset(&r, 0, sizeof(r));
	while (reply_location) {

		reply_lock.l_start = reply_location;
		fcntl(fd, F_OFD_SETLKW, &reply_lock);

		lseek(fd, reply_location, SEEK_SET);
		read(fd, &r, sizeof(r));

		if (!r.next_reply) {
			break;
		}

		reply_location = r.next_reply;

		reply_lock.l_type = F_UNLCK;
		fcntl(fd, F_OFD_SETLKW, &reply_lock);
	}

	lseek(fd, block * MSG_BLOCK_SIZE, SEEK_SET);
	reply->reply_id = ++mm.replies_count;
	printf("add-reply: reply id = %d, mm.replies_count = %d\n", reply->reply_id, mm.replies_count);
	write(fd, reply, sizeof(*reply));

	fdatasync(fd);

	if (reply_location) {
		reply_lock.l_start = reply_location;
		reply_lock.l_type = F_WRLCK;

		fcntl(fd, F_OFD_SETLKW, &reply_lock);
		r.next_reply = block * MSG_BLOCK_SIZE;

		lseek(fd, reply_location, SEEK_SET);
		write(fd, &r, sizeof(r));

		reply_lock.l_type = F_UNLCK;
		fcntl(fd, F_OFD_SETLKW, &reply_lock);
	}
	else {
		msg.first_reply = block * MSG_BLOCK_SIZE;

		lseek(fd, msg_location, SEEK_SET);
		write(fd, &msg, sizeof(msg));

		msglock.l_type = F_UNLCK;
		fcntl(fd, F_OFD_SETLKW, &msglock);
	}

	lseek(fd, 0, SEEK_SET);

	write(fd, block_status, MSG_BV_SIZE);

	write(fd, &mm, sizeof(mm));

	lock.l_start = 0;
	lock.l_len = MSG_BV_SIZE + MSG_BLOCK_SIZE;
	lock.l_type = F_UNLCK;

	fcntl(fd, F_OFD_SETLKW, &lock);

	lock.l_start = next;
	lock.l_len = MSG_BLOCK_SIZE;
	lock.l_type = F_UNLCK;

	free(block_status);
	fdatasync(fd);

	close(fd);

	return reply->reply_id;
}

char *serialize_reply_array(struct reply **replies, int len) {
	char *prev = malloc(1);
	prev[0] = 0;
	for (int i = 0; i < len; i++) {
		char *temp = serialize_reply(replies[i]);
		char *t = NULL;

		asprintf(&t, i == 0 ? "%s%s" : "%s, %s", prev, temp);

		free(prev);
		free(temp);

		prev = t;
	}

	char *array = NULL;

	asprintf(&array, "[%s]", prev);
	free(prev);

	return array;
}

char *serialize_reply(struct reply *reply) {
	char *str = NULL;

	printf("reply_id = %d\n", reply->reply_id);
	asprintf(&str, "{\"id\": %d, \"owner_id\": %d, \"content\": \"%s\"}",

			reply->reply_id, reply->owner_id,
			reply->content);
	return str;
}

struct reply **get_all_replies(int category_id, int msg_id, int *len) {
	int fd = open(MSG_FILE, O_RDONLY);
	struct messagemeta mm;

	struct flock lock = {
		.l_start = MSG_BV_SIZE,
		.l_whence = SEEK_SET,
		.l_type = F_RDLCK,
		.l_len = MSG_BLOCK_SIZE,
		.l_pid = 0,
	};

	fcntl(fd, F_OFD_SETLKW, &lock);

	lseek(fd, MSG_BV_SIZE, SEEK_SET);

	read(fd, &mm, sizeof(mm));

	lock.l_type = F_UNLCK;

	fcntl(fd, F_OFD_SETLKW, &lock);

	struct category c;

	off_t next = mm.first_category;

	while (next) {
		lock.l_start = next;
		fcntl(fd, F_OFD_SETLKW, &lock);

		lseek(fd, next, SEEK_SET);

		read(fd, &c, sizeof(c));

		if (c.cat_id == category_id) {
			break;
		}

		lock.l_type = F_UNLCK;
		fcntl(fd, F_OFD_SETLKW, &lock);

		next = c.next_category;
	}

	if (!next) {
		close(fd);
		return NULL;
	}

	struct message message;
	off_t msg_location = c.first_message;

	while (msg_location) {
		struct flock msglock = {
			.l_whence = SEEK_SET,
			.l_len = MSG_BLOCK_SIZE,
			.l_start = msg_location,
			.l_pid = 0,
			.l_type = F_RDLCK,
		};

		fcntl(fd, F_OFD_SETLKW, &msglock);

		lseek(fd, msg_location, SEEK_SET);

		read(fd, &message, sizeof(message));

		if (message.msg_id == msg_id) {
			break;
		}

		msglock.l_type = F_UNLCK;

		fcntl(fd, F_OFD_SETLKW, &msglock);

		msg_location = message.next_message;
	}

	if (!msg_location) {
		close(fd);
		return 0;
	}

	int i = 0;
	int size = 20;

	struct reply **replies = malloc(sizeof(*replies) * size);
	off_t reply_location = message.first_reply;

	while (reply_location) {
		struct flock reply_lock = {
			.l_whence = SEEK_SET,
			.l_start = reply_location,
			.l_len = MSG_BLOCK_SIZE,
			.l_pid = 0,
			.l_type = F_RDLCK,
		};

		fcntl(fd, F_OFD_SETLKW, &reply_lock);
		lseek(fd, reply_location, SEEK_SET);

		replies[i] = malloc(sizeof(**replies));

		read(fd, replies[i], sizeof(**replies));

		if (i == size) {
			size += 20;
			replies = realloc(replies, sizeof(*replies) * size);
		}

		reply_location = replies[i]->next_reply;

		reply_lock.l_type = F_UNLCK;
		fcntl(fd, F_OFD_SETLKW, &reply_lock);
		i++;
	}

	replies = realloc(replies, sizeof(*replies) * i);

	*len = i;

	lock.l_type = F_UNLCK;

	fcntl(fd, F_OFD_SETLKW, &lock);

	close(fd);

	return replies;
}

int delete_category(int category_id, int owner_id) {
	int fd = open(MSG_FILE, O_RDWR);
	struct messagemeta mm;

	struct flock lock = {
		.l_start = MSG_BV_SIZE,
		.l_whence = SEEK_SET,
		.l_type = F_RDLCK,
		.l_len = MSG_BLOCK_SIZE,
		.l_pid = 0,
	};

	lseek(fd, MSG_BV_SIZE, SEEK_SET);
	read(fd, &mm, sizeof(mm));

	struct category c, update;

	off_t category_location = mm.first_category, prev;

	struct flock cat_lock = {
		.l_whence = SEEK_SET,
		.l_len = MSG_BLOCK_SIZE,
		.l_pid = 0,
	};

	while (category_location) {
		cat_lock.l_start = category_location;
		cat_lock.l_type = F_RDLCK;

		fcntl(fd, F_OFD_SETLKW, &cat_lock);
		lseek(fd, category_location, SEEK_SET);
		read(fd, &c, sizeof(c));

		if (c.cat_id == category_id) {
			if (c.owner_id != owner_id) {
				close(fd);
				return 0;
			}
			break;
		}
		prev = category_location;
		category_location = c.next_category;

		cat_lock.l_type = F_UNLCK;
		fcntl(fd, F_OFD_SETLKW, &cat_lock);
	}

	if (!category_location) {
		close(fd);
		return 0;
	}

	char *block_status = malloc(MSG_BV_SIZE);
	lseek(fd, 0, SEEK_SET);
	read(fd, block_status, MSG_BV_SIZE);

	delete_all_messages(fd, c.first_message, block_status);

	set_block_empty(block_status, category_location / MSG_BLOCK_SIZE);

	if (category_location == mm.first_category) {
		lock.l_type = F_WRLCK;
		lock.l_len = MSG_BLOCK_SIZE;
		fcntl(fd, F_OFD_SETLKW, &lock);
		lseek(fd, MSG_BV_SIZE, SEEK_SET);
		mm.first_category = c.next_category;
		write(fd, &mm, sizeof(mm));

		lock.l_type = F_UNLCK;
		fcntl(fd, F_OFD_SETLKW, &lock);
	}
	else {

		lseek(fd, prev, SEEK_SET);
		read(fd, &update, sizeof(update));
		update.next_category = c.next_category;
		lseek(fd, prev, SEEK_SET);
		write(fd, &update, sizeof(update));
	}

	lock.l_len = MSG_BV_SIZE;
	lock.l_start = 0;
	lock.l_type = F_WRLCK;
	lseek(fd, 0, SEEK_SET);
	fcntl(fd, F_OFD_SETLKW, &lock);

	write(fd, block_status, MSG_BV_SIZE);

	lock.l_type = F_UNLCK;
	fcntl(fd, F_OFD_SETLKW, &lock);

	close(fd);

	return 1;
}

void delete_all_messages(int fd, off_t message, char *block_status) {
	struct message m;
	while (message) {
		struct flock msg_lock = {
			.l_whence = SEEK_SET,
			.l_len = MSG_BLOCK_SIZE,
			.l_start = message,
			.l_pid = 0,
			.l_type = F_RDLCK,
		};
		fcntl(fd, F_OFD_SETLKW, &msg_lock);

		lseek(fd, message, SEEK_SET);
		read(fd, &m, sizeof(m));
		delete_all_replies(fd, m.first_reply, block_status);
		set_block_empty(block_status, message / MSG_BLOCK_SIZE);
		message = m.next_message;

		msg_lock.l_type = F_UNLCK;
		fcntl(fd, F_OFD_SETLKW, &msg_lock);
	}
	return;
}

int delete_message(int category_id, int msg_id, int owner_id) {
	int fd = open(MSG_FILE, O_RDWR);
	struct messagemeta mm;

	struct flock lock = {
		.l_start = 0,
		.l_whence = SEEK_SET,
		.l_type = F_RDLCK,
		.l_len = MSG_BV_SIZE + MSG_BLOCK_SIZE,
		.l_pid = 0,
	};

	lseek(fd, MSG_BV_SIZE, SEEK_SET);
	read(fd, &mm, sizeof(mm));

	struct category c;

	off_t category_location = mm.first_category;
	struct flock cat_lock = {
		.l_whence = SEEK_SET,
		.l_len = MSG_BLOCK_SIZE,
		.l_pid = 0,
	};

	while (category_location) {
		cat_lock.l_start = category_location;
		cat_lock.l_type = F_RDLCK;

		fcntl(fd, F_OFD_SETLKW, &cat_lock);
		lseek(fd, category_location, SEEK_SET);
		read(fd, &c, sizeof(c));

		if (c.cat_id == category_id) {
			break;
		}

		category_location = c.next_category;

		cat_lock.l_type = F_UNLCK;
		fcntl(fd, F_OFD_SETLKW, &cat_lock);
	}

	if (!category_location) {
		close(fd);
		return 0;
	}

	off_t msg_location = c.first_message, prev;
	struct message m, update;
	struct flock msg_lock = {
		.l_whence = SEEK_SET,
		.l_len = MSG_BLOCK_SIZE,
		.l_pid = 0,
	};

	while (msg_location) {
		msg_lock.l_start = msg_location;
		msg_lock.l_type = F_RDLCK;

		fcntl(fd, F_OFD_SETLKW, &msg_lock);

		lseek(fd, msg_location, SEEK_SET);
		read(fd, &m, sizeof(m));

		if (m.msg_id == msg_id) {
			if (owner_id != m.owner_id) {
				close(fd);
				return 0;
			}
			break;
		}
		prev = msg_location;
		msg_location = m.next_message;
		msg_lock.l_type = F_UNLCK;
		fcntl(fd, F_OFD_SETLKW, &msg_lock);
	}

	if (!msg_location) {
		close(fd);
		return 0;
	}

	struct reply r;
	off_t reply = m.first_reply;

	lock.l_start = 0;
	lock.l_whence = SEEK_SET;
	lock.l_type = F_WRLCK;
	lock.l_len = MSG_BV_SIZE;
	lock.l_pid = 0;
	fcntl(fd, F_OFD_SETLKW, &lock);

	lseek(fd, 0, SEEK_SET);

	char *block_status = malloc(MSG_BV_SIZE);

	read(fd, block_status, MSG_BV_SIZE);

	delete_all_replies(fd, reply, block_status);

	m.first_reply = 0;

	set_block_empty(block_status, msg_location / MSG_BLOCK_SIZE);

	lseek(fd, 0, SEEK_SET);

	write(fd, block_status, MSG_BV_SIZE);

	if (msg_location == c.first_message) {
		cat_lock.l_type = F_WRLCK;
		fcntl(fd, F_OFD_SETLKW, &cat_lock);

		c.first_message = m.next_message;

		lseek(fd, category_location, SEEK_SET);
		write(fd, &c, sizeof(c));
		cat_lock.l_type = F_UNLCK;
		fcntl(fd, F_OFD_SETLKW, &cat_lock);
	}
	else {
		msg_lock.l_start = prev;
		msg_lock.l_type = F_WRLCK;

		lseek(fd, prev, SEEK_SET);
		read(fd, &update, sizeof(update));

		update.next_message = m.next_message;

		lseek(fd, prev, SEEK_SET);
		write(fd, &update, sizeof(update));

		msg_lock.l_start = prev;
		msg_lock.l_type = F_WRLCK;
	}

	lock.l_type = F_UNLCK;
	fcntl(fd, F_OFD_SETLKW, &lock);

	close(fd);

	return 1;
}

void delete_all_replies(int fd, off_t reply, char *block_status) {
	struct reply r;
	while (reply) {
		struct flock reply_lock = {
			.l_whence = SEEK_SET,
			.l_len = MSG_BLOCK_SIZE,
			.l_start = reply,
			.l_pid = 0,
			.l_type = F_RDLCK,
		};
		fcntl(fd, F_OFD_SETLKW, &reply_lock);

		lseek(fd, reply, SEEK_SET);
		read(fd, &r, sizeof(r));
		set_block_empty(block_status, reply / MSG_BLOCK_SIZE);
		reply = r.next_reply;

		reply_lock.l_type = F_UNLCK;
		fcntl(fd, F_OFD_SETLKW, &reply_lock);
	}
	return;
}

int delete_reply(int category_id, int msg_id, int reply_id, int owner_id) {
	int fd = open(MSG_FILE, O_RDWR);
	struct messagemeta mm;

	struct flock lock = {
		.l_start = 0,
		.l_whence = SEEK_SET,
		.l_type = F_WRLCK,
		.l_len = MSG_BV_SIZE + MSG_BLOCK_SIZE,
		.l_pid = 0,
	};

	fcntl(fd, F_OFD_SETLKW, &lock);

	lseek(fd, MSG_BV_SIZE, SEEK_SET);

	read(fd, &mm, sizeof(mm));

	struct category c;

	off_t next = mm.first_category;

	while (next) {
		lock.l_start = next;
		fcntl(fd, F_OFD_SETLKW, &lock);

		lseek(fd, next, SEEK_SET);

		read(fd, &c, sizeof(c));

		if (c.cat_id == category_id) {
			break;
		}

		lock.l_type = F_UNLCK;
		fcntl(fd, F_OFD_SETLKW, &lock);

		next = c.next_category;
	}

	if (!next) {
		close(fd);
		return 0;
	}

	struct message message;
	off_t msg_location = c.first_message;
	struct flock msglock = {
		.l_whence = SEEK_SET,
		.l_len = MSG_BLOCK_SIZE,
		.l_start = msg_location,
		.l_pid = 0,
		.l_type = F_RDLCK,
	};

	while (msg_location) {
		fcntl(fd, F_OFD_SETLKW, &msglock);

		lseek(fd, msg_location, SEEK_SET);

		read(fd, &message, sizeof(message));

		if (message.msg_id == msg_id) {
			break;
		}

		msglock.l_type = F_UNLCK;

		fcntl(fd, F_OFD_SETLKW, &msglock);

		msg_location = message.next_message;
	}

	if (!msg_location) {
		close(fd);
		return 0;
	}


	struct reply cur, update;
	off_t reply_location = message.first_reply, prev;

	struct flock reply_lock = {
		.l_whence = SEEK_SET,
		.l_len = MSG_BLOCK_SIZE,
		.l_start = reply_location,
		.l_pid = 0,
	};

	while (reply_location) {
		reply_lock.l_type = F_RDLCK;
		fcntl(fd, F_OFD_SETLKW, &reply_lock);
		lseek(fd, reply_location, SEEK_SET);
		read(fd, &cur, sizeof(cur));
		if (cur.reply_id == reply_id) {
			if (cur.owner_id != owner_id) {
				close(fd);
				return 0;
			}
			break;
		}
		prev = reply_location;
		reply_location = cur.next_reply;
		reply_lock.l_type = F_UNLCK;
		fcntl(fd, F_OFD_SETLKW, &reply_lock);
	}

	if (!reply_location) {
		close(fd);
		return 0;
	}

	lseek(fd, 0, SEEK_SET);

	char *block_status = malloc(MSG_BV_SIZE);
	read(fd, block_status, MSG_BLOCK_SIZE);
	set_block_empty(block_status, reply_location / MSG_BLOCK_SIZE);

	lseek(fd, 0, SEEK_SET);
	write(fd, block_status, MSG_BV_SIZE);

	free(block_status);

	if (reply_location && reply_location == message.first_reply) {
		msglock.l_type = F_WRLCK;
		fcntl(fd, F_OFD_SETLKW, &msglock);
		message.first_reply = cur.next_reply;
		lseek(fd, msg_location, SEEK_SET);
		write(fd, &message, sizeof(message));
		msglock.l_type = F_UNLCK;
		fcntl(fd, F_OFD_SETLKW, &msglock);
	}
	else {
		reply_lock.l_start = prev;
		reply_lock.l_type = F_WRLCK;
		fcntl(fd, F_OFD_SETLKW, &reply_lock);
		lseek(fd, prev, SEEK_SET);
		read(fd, &update, sizeof(update));
		update.next_reply = cur.next_reply;
		lseek(fd, prev, SEEK_SET);
		write(fd, &update, sizeof(update));
		reply_lock.l_type = F_UNLCK;
		fcntl(fd, F_OFD_SETLKW, &reply_lock);
	}

	lock.l_type = F_UNLCK;

	fcntl(fd, F_OFD_SETLKW, &lock);

	close(fd);

	return 1;
}

void initialize_blob_file(char *filename, int total_blocks, int filled_blocks, int free_blocks) {
	initialize_bit_vector(filename, total_blocks, filled_blocks);
	int fd = open("db/blobs", O_RDWR);
	struct filemeta fm;
	memset(&fm, 0, sizeof(fm));
	fm.remaining_blocks = free_blocks;
	lseek(fd, FL_BV_SIZE, SEEK_SET);
	write(fd, &fm, sizeof(fm));
	close(fd);
}

int add_file(char *filedata, ssize_t filesize, char *filename, int owner_id) {
	int file_fd = open("db/blobs", O_RDWR), block;
	struct filemeta fm;
	struct flock lock = {
		.l_whence = SEEK_SET,
		.l_start = 0,
		.l_len = FL_BV_SIZE + FL_BLOCK_SIZE,
		.l_type = F_WRLCK,
		.l_pid = 0,
	};
	struct user *u = get_user(owner_id);

	if (!u) {
		close(file_fd);
		return 0;
	}

	char *block_status = malloc(FL_BV_SIZE);
	read(file_fd, block_status, FL_BV_SIZE);

	read(file_fd, &fm, sizeof(fm));

	off_t next = u->first_file_location, prev;

	if (filesize > fm.remaining_blocks * FL_BLOCK_SIZE) {
		free(block_status);
		close(file_fd);
		return 0;
	}
	// the number of blocks required for the file
	int required_blocks = filesize  / FL_BLOCK_SIZE + 1;
	// the file heads required to store blocks location
	int required_heads = required_blocks / 476 + 1;

	struct filehead fheads[required_heads];
	memset(fheads, 0, sizeof(fheads));

	required_blocks += required_heads;

	off_t blocks[required_blocks], j = 0, i;

	for (block = FL_BV_SIZE / FL_BLOCK_SIZE + 1; j < required_blocks && block < FL_BLOCKS_TOTAL; block++) {
		if (!is_block_free(block_status, block)) {
			continue;
		}
		set_block_full(block_status, block);
		blocks[j++] = block;
	}

	// not enough blocks for file to fit
	if (j != required_blocks) {
		free(block_status);
		free(u);
		close(file_fd);
		return 0;
	}

	struct flock file_lock = {
		.l_whence = SEEK_SET,
		.l_len = FL_BLOCK_SIZE,
		.l_pid = 0,
	};

	j = 0;

	// first file head of a file contains all data for that file
	fheads[0].owner_id = owner_id;
	fheads[0].filesize = filesize;
	fheads[0].file_id = ++fm.file_count;
	fheads[0].next_file = u->first_file_location;
	strcpy(fheads[0].name, filename);


	while (filesize > 0) {
		file_lock.l_type = F_WRLCK;
		file_lock.l_start = blocks[j++] * FL_BLOCK_SIZE;

		fcntl(file_fd, F_OFD_SETLKW, file_lock);

		ssize_t min = filesize < FL_BLOCK_SIZE ? filesize : FL_BLOCK_SIZE;

		lseek(file_fd, file_lock.l_start, SEEK_SET);
		write(file_fd, filedata, min);

		file_lock.l_type = F_UNLCK;
		fcntl(file_fd, F_OFD_SETLKW, &file_lock);

		filedata += min;
		filesize -= min;
	}

	int temp = required_blocks;
	for (int k = 0; j < required_blocks; j++, k++) {
		int min = temp - required_heads < 476 ? temp - required_heads : 476;
		for (i = 0; i < min; i++) {
			fheads[k].blocks[i] = blocks[i + k * 476] * FL_BLOCK_SIZE;
		}
		fheads[k].next_blocks = (j + 1 < required_blocks ? blocks[j + 1] : 0) * FL_BLOCK_SIZE;
		temp -= min;
	}

	for (j = required_blocks - required_heads, i = 0; j < required_blocks; j++, i++) {
		file_lock.l_type = F_WRLCK;
		file_lock.l_start = blocks[j] * FL_BLOCK_SIZE;
		fcntl(file_fd, F_OFD_SETLKW, &file_lock);

		lseek(file_fd, file_lock.l_start, SEEK_SET);
		write(file_fd, fheads + i, sizeof(fheads[i]));

		file_lock.l_type = F_UNLCK;
		fcntl(file_fd, F_OFD_SETLKW, &file_lock);
	}

	u->first_file_location = blocks[(required_blocks - required_heads)] * FL_BLOCK_SIZE;

	// update the user structure
	update_user(u);

	free(u);

	fm.remaining_blocks -= required_blocks;

	lock.l_start = 0;
	lock.l_type = F_WRLCK;
	lock.l_len = FL_BV_SIZE;
	fcntl(file_fd, F_OFD_SETLKW, &lock);

	lseek(file_fd, 0, SEEK_SET);
	write(file_fd, block_status, FL_BV_SIZE);
	write(file_fd, &fm, sizeof(fm));

	close(file_fd);

	return fheads[0].file_id;
}

struct filehead **get_all_files(int owner_id, int *len) {
	int file_fd;
	struct user *u = get_user(owner_id);

	if (!u) {
		*len = 0;
		return NULL;
	}

	int size = 20, i = 0;
	struct filehead **fheads;
	off_t next = u->first_file_location;

	if (!next) {
		*len = 0;
		return NULL;
	}
	fheads = malloc(sizeof(*fheads) * size);
	file_fd = open(FL_FILE, O_RDONLY);

	while (next) {
		struct flock file_lock = {
			.l_start = next,
			.l_len = FL_BLOCK_SIZE,
			.l_type = F_RDLCK,
			.l_pid = 0,
			.l_whence = SEEK_SET,
		};

		fcntl(file_fd, F_OFD_SETLKW, &file_lock);
		lseek(file_fd, next, SEEK_SET);

		fheads[i] = malloc(sizeof(**fheads));

		read(file_fd, fheads[i], sizeof(**fheads));

		next = fheads[i]->next_file;

		i++;
		if (i == size) {
			size += 20;
			fheads = realloc(fheads, sizeof(**fheads) * size);
		}

		file_lock.l_type = F_UNLCK;
		fcntl(file_fd, F_OFD_SETLKW, &file_lock);
	}
	fheads = realloc(fheads, sizeof(**fheads) * i);

	*len = i;

	close(file_fd);

	return fheads;
}

char *serialize_file_array(struct filehead **fheads, int len) {
	char *prev = malloc(1);
	prev[0] = 0;
	for (int i = 0; i < len; i++) {
		char *temp = serialize_file(fheads[i]);
		char *t = NULL;

		asprintf(&t, i == 0 ? "%s%s" : "%s, %s", prev, temp);

		free(prev);
		free(temp);

		prev = t;
	}

	char *array = NULL;

	asprintf(&array, "[%s]", prev);
	free(prev);

	return array;
}

char *serialize_file(struct filehead *fhead) {
	char *str = NULL;

	asprintf(&str, "{\"id\": %d, \"owner_id\": %d, \"filename\": \"%s\", \"filesize\": %ld}",
			fhead->file_id, fhead->owner_id,
			fhead->name, fhead->filesize);
	return str;
}

ssize_t get_file(int user_id, int file_id, char **filedata, char **filename) {
	int file_fd;
	struct user *u = get_user(user_id);

	struct flock lock = {
		.l_whence = SEEK_SET,
		.l_len = FL_BLOCK_SIZE,
		.l_pid = 0,
	};

	if (!u) {
		return 0;
	}

	file_fd = open(FL_FILE, O_RDONLY);
	off_t next = u->first_file_location;

	free(u);

	struct filehead fh;

	while (next) {
		lock.l_start = next;
		lock.l_type = F_RDLCK,
		fcntl(file_fd, F_OFD_SETLKW, &lock);
		lseek(file_fd, next, SEEK_SET);

		read(file_fd, &fh, sizeof(fh));

		if (fh.file_id == file_id) {
			break;
		}

		lock.l_type = F_UNLCK,
		fcntl(file_fd, F_OFD_SETLKW, &lock);

		next = fh.next_file;
	}

	if (!next) {
		close(file_fd);
		return 0;
	}

	*filename = malloc(strlen(fh.name) + 1);
	strcpy(*filename, fh.name);
	ssize_t temp = fh.filesize, filesize = fh.filesize;
	char *file = malloc(fh.filesize);
	ssize_t i = 0;

	do {
		lock.l_start = next;
		lock.l_type = F_RDLCK;
		fcntl(file_fd, F_OFD_SETLKW, &lock);
		lseek(file_fd, next, SEEK_SET);
		read(file_fd, &fh, sizeof(fh));
		for (int j = 0; j < 476 && fh.blocks[j]; j++) {
			ssize_t min = temp < FL_BLOCK_SIZE ? temp : FL_BLOCK_SIZE;
			lseek(file_fd, fh.blocks[j], SEEK_SET);
			read(file_fd, file + i, min);
			temp -= min;
			i += min;
		}
		lock.l_type = F_UNLCK;
		fcntl(file_fd, F_OFD_SETLKW, &lock);
		next = fh.next_blocks;
	} while (next);

	*filedata = file;

	close(file_fd);

	return filesize;
}

int delete_file(int user_id, int file_id) {
	int file_fd;
	struct user *u = get_user(user_id);

	if (!u) {
		return 0;
	}

	struct flock lock = {
		.l_type = F_WRLCK,
		.l_pid = 0,
		.l_len = FL_BLOCK_SIZE,
	};

	file_fd = open(FL_FILE, O_RDWR);
	off_t next = u->first_file_location, prev = 0;

	struct filehead fh;
	struct filemeta fm;

	while (next) {
		lock.l_start = next;
		lock.l_type = F_RDLCK,
		fcntl(file_fd, F_OFD_SETLKW, &lock);

		lseek(file_fd, next, SEEK_SET);

		read(file_fd, &fh, sizeof(fh));

		if (fh.file_id == file_id) {
			break;
		}

		prev = next;
		next = fh.next_file;

		lock.l_type = F_UNLCK;
		fcntl(file_fd, F_OFD_SETLKW, &lock);
	}

	if (!next) {
		close(file_fd);
		return 0;
	}

	off_t next_file = fh.next_file;

	lock.l_start = 0;
	lock.l_len = FL_BV_SIZE + FL_BLOCK_SIZE;
	lock.l_type = F_WRLCK;

	char *block_status = malloc(FL_BV_SIZE);

	lseek(file_fd, 0, SEEK_SET);
	read(file_fd, block_status, FL_BV_SIZE);

	read(file_fd, &fm, sizeof(fm));
	set_block_empty(block_status, next / FL_BLOCK_SIZE);

	fm.remaining_blocks++;

	struct flock f_lock = {
		.l_len = FL_BLOCK_SIZE,
		.l_whence = SEEK_SET,
		.l_type = F_WRLCK,
		.l_start = next,
		.l_pid = 0,
	};

	fcntl(file_fd, F_OFD_SETLKW, &f_lock);

	while (1) {
		for (int block = 0; block < 476 && fh.blocks[block]; block++) {
			set_block_empty(block_status, fh.blocks[block] / FL_BLOCK_SIZE);
			fm.remaining_blocks++;
		}
		if (!fh.next_blocks) {
			break;
		}
		set_block_empty(block_status, fh.next_blocks / FL_BLOCK_SIZE);
		fm.remaining_blocks++;
		f_lock.l_start = fh.next_blocks;
		f_lock.l_type = F_WRLCK;
		lseek(file_fd, fh.next_blocks, SEEK_SET);
		read(file_fd, &fh, sizeof(fh));
	}
	
	if (!prev) {
		u->first_file_location = next_file;
		update_user(u);
	}
	else {
		f_lock.l_start = prev;
		lseek(file_fd, prev, SEEK_SET);
		struct filehead update;
		fcntl(file_fd, F_OFD_SETLKW, &f_lock);
		read(file_fd, &update, sizeof(update));
		update.next_file = next_file;
		lseek(file_fd, prev, SEEK_SET);
		write(file_fd, &update, sizeof(update));
	}

	lseek(file_fd, 0, SEEK_SET);
	write(file_fd, block_status, FL_BV_SIZE);
	write(file_fd, &fm, sizeof(fm));

	free(block_status);
	free(u);

	close(file_fd);

	return 1;
}

