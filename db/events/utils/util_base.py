from sqlalchemy.orm import Session
from sqlalchemy import func, create_engine
from rich import print as rprint
from time import sleep
from os.path import join, exists
from events import Event


def wrapper(results, output, print_procname, follow, filter, args):
    db_path = join(results, "plugins.db")
    if not exists(db_path):
        print(f"Failed to find db at {db_path}. Check your --results")
        return
    engine = create_engine(f"sqlite:///{db_path}")
    with open(output, "w") as f:
        with Session(engine) as sess:
            highest_id = -1

            # only pretty print if we are printing to stdout
            if output == "/dev/stdout":
                printer = rprint
            else:
                printer = print

            # in follow mode we print the last 4 events and then continue from there
            if follow:
                if id_num := sess.execute(func.max(Event.id)).first():
                    highest_id = id_num[0] - 4
            while True:
                query = filter(sess, *args)

                if highest_id != -1:
                    query = query.filter(Event.id > highest_id)

                for event in query.all():
                    if print_procname:
                        printer(f"({event.procname}) {event}", file=f)
                    else:
                        printer(event, file=f)
                    highest_id = max(highest_id, event.id)

                if not follow:
                    break
                else:
                    sleep(1)
