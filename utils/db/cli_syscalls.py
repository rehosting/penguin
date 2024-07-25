import click
from sqlalchemy.orm import Session
from sqlalchemy import func, create_engine
from rich import print
from time import sleep
from db import Event, Syscall
from os.path import join
from sqlalchemy.orm import Mapped
from sqlalchemy import ForeignKey
from typing import Optional




@click.command()
@click.option('--results', default="results", help="Path to results folder (default is ./results/)")
@click.option('--procname', default=None, help="Process name to filter for (looks for substring)")
@click.option('--syscall', default=None, help="Syscall name to filter for (looks for substring)")
@click.option('--errors', default=False, help="Just show syscalls that returned an error", is_flag=True)
@click.option('--follow', default=False, help="Show latest results as they appear", is_flag=True)
@click.option('--output', default="/dev/stdout", help="Output to file instead of stdout")
def query_syscall(results, procname, syscall, errors, follow, output):
    db_path = join(results, "plugins.db")
    engine = create_engine(f"sqlite:///{db_path}")
    with open(output, "w") as f:
        with Session(engine) as sess:
            highest_id = -1
        
            # in some cases we want to print the procname
            print_procname = True

            # in follow mode we print the last 4 events and then continue from there
            if follow:
                if id_num := sess.execute(func.max(Event.id)).first():
                    highest_id = id_num[0] - 4
            while True:
                query = sess.query(Syscall)
                if procname:
                    query = query.filter(Syscall.procname.contains(procname))
                    print_procname = False
                if syscall:
                    if not syscall.startswith("sys_"):
                        syscall = "sys_" + syscall
                    query = query.filter(Syscall.name.contains(syscall))
                    # overrides all other run options
                    pass
                
                if errors:
                    query = query.filter(Syscall.retno < 0)
            
                if highest_id != -1:
                    query = query.filter(Syscall.id > highest_id)
            
                for event in query.all():
                    if print_procname:
                        print(f"({event.procname}) {event}", file=f)
                    else:
                        print(event, file=f)
                    highest_id = max(highest_id, event.id)
                
                if not follow:
                    break
                else:
                    sleep(1)

if __name__ == "__main__":
    query_syscall()