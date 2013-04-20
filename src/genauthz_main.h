#ifndef GA_MAIN_H
    #define GA_MAIN_H

#include <event2/event.h>

struct event_base *get_event_base(void);
void set_event_base(struct event_base *base);

#endif /* GA_MAIN_H */
