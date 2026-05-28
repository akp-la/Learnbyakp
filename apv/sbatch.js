
        const API_URL = "https://learnbyakp.onrender.com/api/science/batches";
        const container = document.getElementById("course-container");

        // Skeleton Loader UI
        const skeletonHTML = `
            <div class="bg-white rounded-2xl border-2 border-gray-200 shadow-xl overflow-hidden">
                <div class="animate-pulse bg-gray-200 h-[225px] w-full"></div>
                <div class="p-4">
                    <div class="animate-pulse bg-gray-200 h-5 w-3/4 mb-4 rounded"></div>
                    <div class="animate-pulse bg-gray-200 h-5 w-1/4 mb-4 rounded"></div>
                    <div class="animate-pulse bg-gray-200 h-12 w-full mt-4 rounded"></div>
                </div>
            </div>
        `;

        // Fetch Data from API
        async function fetchBatches() {
            // Show loading skeletons initially (3 items)
            container.innerHTML = skeletonHTML.repeat(3);

            try {
                const response = await fetch(API_URL);
                if (!response.ok) throw new Error("Failed to fetch batches");
                
                const result = await response.json();

                if (result.status === 200 && Array.isArray(result.data)) {
                    renderBatches(result.data);
                } else {
                    throw new Error(result.message || "Unexpected data format");
                }
            } catch (error) {
                // Show error message if API fails
                container.innerHTML = `<p class="text-red-500 text-center col-span-full text-lg font-semibold">Error: ${error.message}</p>`;
            }
        }

        // Render API Data to HTML
        function renderBatches(batches) {
            container.innerHTML = ""; // Clear skeletons

            batches.forEach(batch => {
                const card = document.createElement("div");
                card.className = "bg-white rounded-2xl border-2 border-gray-200 shadow-xl overflow-hidden transition-transform hover:scale-105 duration-300 flex flex-col";

                card.innerHTML = `
                    <div class="relative">
                        <img src="${batch.course_thumbnail}" alt="${batch.course_name}" class="w-full h-[225px] object-cover">
                    </div>
                    <div class="p-4 flex flex-col flex-grow">
                        <h3 class="text-md font-bold text-gray-800 flex-grow min-h-[40px]">${batch.course_name}</h3>
                        <div class="flex items-center justify-between mt-4">
                            <p class="text-2xl font-bold text-black">Free</p>
                        </div>
                        <button 
                            onclick="window.location.href='/scienceandfun/batch?id=${batch.id}&title=${encodeURIComponent(batch.course_name)}'" 
                            class="w-full mt-4 bg-black hover:bg-gray-800 text-white font-bold py-3 rounded-lg transition-colors">
                            View Content
                        </button>
                    </div>
                `;
                
                container.appendChild(card);
            });
        }

        // Initialize fetching on page load
        fetchBatches();
    
