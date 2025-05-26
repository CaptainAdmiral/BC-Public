from pydantic import TypeAdapter


TYPE_ADAPTERS: dict[type, TypeAdapter] = {}

def get_type_adapter(tp):
    if tp in TYPE_ADAPTERS:
        return TYPE_ADAPTERS[tp]
    else:
        adapter = TypeAdapter(tp)
        TYPE_ADAPTERS[tp] = adapter
        return adapter