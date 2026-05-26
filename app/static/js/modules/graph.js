window.GraphModule = {

    instances: {}, // tabId → graph instance

    init() {
        console.log("[Graph] init");
    },

    // ==========================
    // CREATE GRAPH FOR TAB
    // ==========================
    create(tabId) {

        const container = document.getElementById("cy");

        if (!container) {
            console.warn("[Graph] no container");
            return;
        }

        const cy = cytoscape({

            container,

            style: [
                {
                    selector: 'node',
                    style: {
                        'label': 'data(label)',
                        'background-color': '#3b82f6',
                        'color': '#fff',
                        'font-size': 8,
                        'text-valign': 'center',
                        'text-halign': 'center'
                    }
                },

                {
                    selector: '.root',
                    style: {
                        'background-color': '#ef4444'
                    }
                },

                {
                    selector: '.pivot',
                    style: {
                        'background-color': '#f59e0b'
                    }
                },

                {
                    selector: 'edge',
                    style: {
                        'width': 1,
                        'line-color': '#334155'
                    }
                }
            ],

            elements: []
        });

        this.instances[tabId] = {
            cy,
            nodes: [],
            edges: []
        };

        console.log("[Graph] created for tab", tabId);
    },

    // ==========================
    // ADD NODE
    // ==========================
    addNode(tabId, node) {

        const instance = this.instances[tabId];
        if (!instance) return;

        instance.cy.add({
            group: 'nodes',
            data: node
        });

        instance.cy.layout({ name: 'cose' }).run();
    },

    // ==========================
    // ADD EDGE
    // ==========================
    addEdge(tabId, edge) {

        const instance = this.instances[tabId];
        if (!instance) return;

        instance.cy.add({
            group: 'edges',
            data: edge
        });
    },

    // ==========================
    // CLEAR
    // ==========================
    clear(tabId) {

        const instance = this.instances[tabId];
        if (!instance) return;

        instance.cy.elements().remove();
    }
};