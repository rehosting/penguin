import os
import openai
from typing import List, Optional

GPT_MODEL = "gpt-4o"
KNOWLEDGE_DIR = '/docs/llm_knowledge_base'
openai.api_key = os.getenv("OPENAI_API_KEY")

PROMPTS = {
    "config_graph": """Here is a configuration graph. Choose the best, unexplored config to run next. Simply return the UID string and nothing else. If no UID is present in the graph, return 'None'"""
}


class AssistantManager:
    """
    A class to manage OpenAI assistants, threads, and vector stores.
    """

    def __init__(self):
        """
        Initialize the AssistantManager with empty client, assistant, thread, and vector_store.
        """
        self.client: Optional[openai.OpenAI] = None
        self.assistant: Optional[openai.types.Assistant] = None
        self.thread: Optional[openai.types.Thread] = None
        self.vector_store: Optional[openai.types.VectorStore] = None

    def exists_client(self) -> bool:
        """
        Check if the OpenAI client exists.

        Returns:
            bool: True if the client exists, False otherwise.
        """
        return self.client is not None

    def exists_assistant(self) -> bool:
        """
        Check if the assistant exists.

        Returns:
            bool: True if the assistant exists, False otherwise.
        """
        return self.assistant is not None

    def create_assistant(self, name: str, instructions: str, tools: Optional[List[dict]] = None, model: str = GPT_MODEL):
        """
        Create an assistant if it doesn't already exist.

        Args:
            name (str): The name of the assistant.
            instructions (str): Instructions for the assistant.
            tools (Optional[List[dict]]): List of tools for the assistant.
            model (str): The model to use for the assistant.
        """
        if self.exists_assistant():
            return

        self.assistant = self.client.beta.assistants.create(
            name=name,
            instructions=instructions,
            tools=tools,
            model=model,
        )

    def create_run(self, prompt: str) -> str:
        """
        Create a new thread, add a message, and start a run.

        Args:
            prompt (str): The prompt to send to the assistant.

        Returns:
            str: The ID of the created run.
        """
        self.thread = self.client.beta.threads.create()
        self.client.beta.threads.messages.create(thread_id=self.thread.id, role="user", content=prompt)
        run = self.client.beta.threads.runs.create_and_poll(
            thread_id=self.thread.id,
            assistant_id=self.assistant.id,
        )
        len_msgs = len(list(self.client.beta.threads.messages.list(self.thread.id)))
        msg = self.client.beta.threads.messages.list(self.thread.id, run_id=run.id).data[0].content[0].text.value
        print(f'===== MESSAGES [{len_msgs}] =====\n{msg}\n')
        return run.id

    def upload_knowledge_files(self):
        """
        Upload knowledge files to the vector store and update the assistant.
        """
        print('===== Knowledge Files =====')
        file_paths = [os.path.join(self.KNOWLEDGE_DIR, fn) for fn in os.listdir(self.KNOWLEDGE_DIR)]
        for fp in file_paths:
            print(f'[FILE] {fp}')

        file_streams = [open(path, 'rb') for path in file_paths]
        self.vector_store = self.client.beta.vector_stores.create(name="Penguin Tool Documentation")
        file_batch = self.client.beta.vector_stores.file_batches.upload_and_poll(
            vector_store_id=self.vector_store.id,
            files=file_streams
        )
        print(f'\tUPLOAD STATUS: {file_batch.status} => {file_batch.file_counts}\n')
        # XXX API bug, status shows that upload failed, but openai playground displays files correctly

        self.assistant = self.client.beta.assistants.update(
            assistant_id=self.assistant.id,
            tool_resources={"file_search": {"vector_store_ids": [self.vector_store.id]}},
        )

    def select_best_config(self, graph: str, prompt: str) -> str:
        """
        Select the best configuration based on the given graph and prompt.

        Args:
            graph (str): The graph to use for configuration selection.
            prompt (str): The prompt to send to the assistant.

        Returns:
            str: The selected configuration as a string.
        """
        if not self.exists_client():
            self.client = openai.OpenAI()

        if not self.exists_assistant():
            llm_name = "llm_rehoster"
            instructions = ""
            self.create_assistant(
                name=llm_name,
                instructions=instructions,
                tools=[{"type": "file_search"}]
            )
            self.upload_knowledge_files()

        full_prompt = f'{prompt}\n\n{graph}'
        print(f'===== PROMPT =====\n{full_prompt}\n')
        run_id = self.create_run(full_prompt)
        uid_str = self.client.beta.threads.messages.list(self.thread.id, run_id=run_id).data[0].content[0].text.value
        return uid_str
