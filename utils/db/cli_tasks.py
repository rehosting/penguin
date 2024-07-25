import click
from sqlalchemy.orm import Session
from sqlalchemy import func, create_engine
from rich import print
from time import sleep
from db import Event 
from os.path import join
from typing import Optional


@click.command()
@click.option('--results', default="results", help="Path to results folder (default is ./results/)")
@click.option('--follow', default=False, help="Show latest results as they appear", is_flag=True)
@click.option('--output', default="/dev/stdout", help="Output to file instead of stdout")
def query_syscall(results, follow, output):
    db_path = join(results, "plugins.db")
    engine = create_engine(f"sqlite:///{db_path}")
    with open(output, "w") as f:
        with Session(engine) as sess:
            highest_id = -1
            seen = set()
        
            # in follow mode we print the last 4 events and then continue from there
            if follow:
                if id_num := sess.execute(func.max(Event.id)).first():
                    highest_id = id_num[0] - 4
            while True:
                query = sess.query(Event)
                if highest_id != -1:
                    query = query.filter(Event.id > highest_id)
            
                for event in query.all():
                    if event.proc_id not in seen:
                        print(f"({event.procname}) {event.proc_id:#x}", file=f)
                        seen.add(event.proc_id)
                    highest_id = max(highest_id, event.id)
                
                if not follow:
                    break
                else:
                    sleep(1)

if __name__ == "__main__":
    query_syscall()