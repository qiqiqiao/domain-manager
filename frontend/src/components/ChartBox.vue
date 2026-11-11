<template>
  <div ref="container" class="chart-container" :style="{ height }"></div>
</template>

<script setup lang="ts">
import { onBeforeUnmount, onMounted, ref, watch } from 'vue'
import * as echarts from 'echarts/core'
import { LineChart, PieChart } from 'echarts/charts'
import {
  GridComponent, LegendComponent, TitleComponent, TooltipComponent,
} from 'echarts/components'
import { CanvasRenderer } from 'echarts/renderers'

echarts.use([
  LineChart, PieChart, GridComponent, LegendComponent, TitleComponent,
  TooltipComponent, CanvasRenderer,
])

const props = withDefaults(defineProps<{ option: any; height?: string }>(), {
  height: '300px',
})

const container = ref<HTMLDivElement>()
let chart: echarts.ECharts | null = null
let observer: ResizeObserver | null = null

function render() {
  if (!chart) return
  chart.setOption(props.option, true)
}

onMounted(() => {
  if (!container.value) return
  chart = echarts.init(container.value)
  render()
  observer = new ResizeObserver(() => chart?.resize())
  observer.observe(container.value)
})

watch(() => props.option, render, { deep: true })

onBeforeUnmount(() => {
  observer?.disconnect()
  chart?.dispose()
  chart = null
})
</script>

<style scoped>
.chart-container {
  width: 100%;
}
</style>
